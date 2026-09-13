extern crate std;
use crate::{
    Config, Counter, MAX_TLVS, Peer,
    parse::{self, Vlan, classify},
};
use std::{vec, vec::Vec};

fn config() -> Config {
    let mut c = Config {
        target_mac: [2, 0, 0, 0, 0, 1],
        local_bssid: [2, 0, 0, 0, 0, 2],
        peer_count: 1,
        r0kh_len: 5,
        ..Config::default()
    };
    c.peers[0] = Peer {
        mac: [2, 0, 0, 0, 1, 1],
        bssid: [2, 0, 0, 0, 1, 2],
    };
    c.r0kh[..5].copy_from_slice(b"local");
    c
}

/// Build a complete wire frame: Ethernet header, inline VLAN 1 tag, RRB
/// header, `auth` TLV bytes, and the 16-byte trailer (zeroed; contents are
/// not validated by the parser).
fn frame(kind: u8, broadcast: bool, auth: &[u8]) -> Vec<u8> {
    let c = config();
    let mut f = Vec::new();
    f.extend(c.target_mac);
    f.extend(c.peers[0].mac);
    f.extend([0x81, 0, 0, 1]); // TPID 0x8100, TCI with VID 1
    f.extend(parse::ETH_P_RRB.to_be_bytes());
    f.extend(parse::RRB_SELECTOR);
    f.extend([kind]);
    f.extend(c.peers[0].bssid);
    f.extend(if broadcast { [255; 6] } else { c.local_bssid });
    f.extend((auth.len() as u16).to_le_bytes());
    f.extend(auth);
    f.extend([0u8; parse::TRAILER_LEN]);
    f
}

fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(tag.to_le_bytes());
    b.extend((value.len() as u16).to_le_bytes());
    b.extend(value);
    b
}

fn accepted(f: &[u8]) -> bool {
    classify(&f, Vlan::default(), &config()).is_ok()
}

#[test]
fn all_five_message_types_and_vlan_representations() {
    for kind in 1..=5 {
        let f = frame(kind, false, &tlv(1, b"nonce"));
        let m = classify(&f.as_slice(), Vlan::default(), &config()).unwrap();
        assert_eq!(m.kind, kind);
        assert_eq!(m.body_offset, parse::ETH_HEADER_LEN + parse::VLAN_TAG_LEN);
        // Same frame with the tag lifted into skb metadata: strip the 4 tag
        // bytes and report the tag through `Vlan` instead.
        let stripped = [&f[..12], &f[16..]].concat();
        let v = Vlan {
            present: true,
            proto: parse::TPID_8021Q,
            tci: 1 | (7 << 13), // VID 1 with PCP 7: PCP must be ignored
        };
        assert!(classify(&stripped.as_slice(), v, &config()).is_ok());
        // The metadata path must enforce the management VID exactly like the
        // inline path (found by ablation: removing `vlan.tci` VID check was
        // not detected by any test before this case existed).
        let wrong_vid = Vlan { tci: 2, ..v };
        assert_eq!(
            classify(&stripped.as_slice(), wrong_vid, &config()).unwrap_err(),
            Counter::Vlan
        );
        assert_eq!(
            classify(&stripped.as_slice(), Vlan::default(), &config()).unwrap_err(),
            Counter::Vlan
        );
        assert!(
            classify(&f.as_slice(), v, &config()).is_err(),
            "extra stacked tag rejected"
        );
    }
}

#[test]
fn scope_mutations_are_rejected_without_mutating_original() {
    let original = frame(5, false, &tlv(1, b"nonce"));
    for offset in [0, 6, 12, 15, 16, 18, 22, 24, 30] {
        let mut f = original.clone();
        f[offset] ^= 0x10;
        let unchanged = f.clone();
        assert!(!accepted(&f), "offset {offset}");
        assert_eq!(f, unchanged);
    }
    for n in 0..original.len() {
        assert!(!accepted(&original[..n]), "truncation {n}");
    }
    // PCP bits live in the high nibble of the first TCI byte: they must not
    // affect matching.
    let mut pcp = original.clone();
    pcp[14] |= 0xe0;
    assert!(accepted(&pcp));
    // A foreign selector (loop-protection-like OUI) must not match.
    let mut loop_protection = original.clone();
    loop_protection[18..23].copy_from_slice(&[0x80, 0x2a, 0xa8, 0, 1]);
    assert!(!accepted(&loop_protection));
    let mut large = original;
    large.resize(crate::MAX_FRAME + 1, 0);
    assert!(!accepted(&large));
}

#[test]
fn broadcast_requires_correct_r0kh_and_request_type() {
    for kind in 1..=5 {
        assert_eq!(
            accepted(&frame(kind, true, &tlv(parse::TLV_R0KH, b"local"))),
            kind == parse::KIND_PULL || kind == parse::KIND_SEQ_REQUEST
        );
        assert!(!accepted(&frame(
            kind,
            true,
            &tlv(parse::TLV_R0KH, b"other")
        )));
        assert!(!accepted(&frame(kind, true, &[])));
    }
    let mut f = frame(
        parse::KIND_SEQ_REQUEST,
        true,
        &tlv(parse::TLV_R0KH, b"local"),
    );
    f[..6].fill(255); // broadcast Ethernet destination is also accepted
    assert!(accepted(&f));
}

#[test]
fn deferred_r0kh_check_preserves_boundaries_and_unicast_scope() {
    for length in [1, 12, crate::MAX_R0KH] {
        let mut c = config();
        c.r0kh_len = length as u8;
        c.r0kh[..length].fill(b'a');
        let auth = [
            tlv(1, b"nonce"),
            tlv(parse::TLV_R0KH, &vec![b'a'; length]),
            tlv(5, b"r1kh"),
        ]
        .concat();
        let f = frame(parse::KIND_SEQ_REQUEST, true, &auth);
        assert!(classify(&f.as_slice(), Vlan::default(), &c).is_ok());
        c.r0kh[length - 1] = b'b';
        assert_eq!(
            classify(&f.as_slice(), Vlan::default(), &c).unwrap_err(),
            Counter::BroadcastScope
        );
    }
    // Remote R0KH values are valid in unicast responses; only broadcasts must
    // name this AP. Deferring the check must not tighten that scope.
    assert!(accepted(&frame(
        parse::KIND_RESPONSE,
        false,
        &tlv(parse::TLV_R0KH, b"remote-r0kh")
    )));
    assert!(!accepted(&frame(
        parse::KIND_SEQ_REQUEST,
        true,
        &tlv(parse::TLV_R0KH, &[])
    )));
    assert!(!accepted(&frame(
        parse::KIND_SEQ_REQUEST,
        true,
        &tlv(parse::TLV_R0KH, &[b'a'; crate::MAX_R0KH + 1])
    )));
}

#[test]
fn tlv_duplicate_overflow_and_count_limits() {
    let a = tlv(parse::TLV_R0KH, b"local");
    assert!(!accepted(&frame(
        parse::KIND_SEQ_REQUEST,
        true,
        &[a.as_slice(), a.as_slice()].concat()
    )));
    // TLV size field that overruns the auth block, and a truncated header.
    assert!(!accepted(&frame(4, false, &[1, 0, 255, 255])));
    assert!(!accepted(&frame(4, false, &[1, 0, 0])));
    // Exactly MAX_TLVS empty TLVs pass; one more exceeds the bounded walk.
    let mut auth = vec![];
    for tag in 0..MAX_TLVS {
        auth.extend(tlv(tag as u16, &[]));
    }
    assert!(accepted(&frame(5, false, &auth)));
    auth.extend(tlv(500, &[]));
    assert!(!accepted(&frame(5, false, &auth)));
}
