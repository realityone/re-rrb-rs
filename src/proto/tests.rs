use crate::proto::{
    Counter, Filter, Local, MAX_TLVS, Peer,
    parse::{self, Vlan, classify},
};
use std::{vec, vec::Vec};

fn filter() -> Filter {
    let mut f = Filter {
        target_mac: [2, 0, 0, 0, 0, 1],
        local_count: 1,
        peer_count: 1,
        ..Filter::default()
    };
    f.locals[0] = Local {
        bssid: [2, 0, 0, 0, 0, 2],
        r0kh_len: 5,
        ..Local::default()
    };
    f.locals[0].r0kh[..5].copy_from_slice(b"local");
    let mut peer = Peer {
        mac: [2, 0, 0, 0, 1, 1],
        bssid_count: 1,
        ..Peer::default()
    };
    peer.bssids[0] = [2, 0, 0, 0, 1, 2];
    f.peers[0] = peer;
    f
}

/// Build a complete wire frame: Ethernet header, inline VLAN 1 tag, RRB
/// header, `auth` TLV bytes, and the 16-byte trailer (zeroed; contents are
/// not validated by the parser).
fn frame(kind: u8, broadcast: bool, auth: &[u8]) -> Vec<u8> {
    let f = filter();
    let mut out = Vec::new();
    out.extend(f.target_mac);
    out.extend(f.peers[0].mac);
    out.extend([0x81, 0, 0, 1]); // TPID 0x8100, TCI with VID 1
    out.extend(parse::ETH_P_RRB.to_be_bytes());
    out.extend(parse::RRB_SELECTOR);
    out.extend([kind]);
    out.extend(f.peers[0].bssids[0]);
    out.extend(if broadcast {
        [255; 6]
    } else {
        f.locals[0].bssid
    });
    out.extend((auth.len() as u16).to_le_bytes());
    out.extend(auth);
    out.extend([0u8; parse::TRAILER_LEN]);
    out
}

fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(tag.to_le_bytes());
    b.extend((value.len() as u16).to_le_bytes());
    b.extend(value);
    b
}

fn accepted(f: &[u8]) -> bool {
    classify(&f, Vlan::default(), &filter()).is_ok()
}

#[test]
fn all_five_message_types_and_vlan_representations() {
    for kind in 1..=5 {
        let f = frame(kind, false, &tlv(1, b"nonce"));
        let m = classify(&f.as_slice(), Vlan::default(), &filter()).unwrap();
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
        assert!(classify(&stripped.as_slice(), v, &filter()).is_ok());
        // The metadata path must enforce the management VID exactly like the
        // inline path (found by ablation: removing `vlan.tci` VID check was
        // not detected by any test before this case existed).
        let wrong_vid = Vlan { tci: 2, ..v };
        assert_eq!(
            classify(&stripped.as_slice(), wrong_vid, &filter()).unwrap_err(),
            Counter::Vlan
        );
        assert_eq!(
            classify(&stripped.as_slice(), Vlan::default(), &filter()).unwrap_err(),
            Counter::Vlan
        );
        assert!(
            classify(&f.as_slice(), v, &filter()).is_err(),
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
    large.resize(crate::proto::MAX_FRAME + 1, 0);
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
    for length in [1, 12, crate::proto::MAX_R0KH] {
        let mut c = filter();
        c.locals[0].r0kh_len = length as u8;
        c.locals[0].r0kh[..length].fill(b'a');
        let auth = [
            tlv(1, b"nonce"),
            tlv(parse::TLV_R0KH, &vec![b'a'; length]),
            tlv(5, b"r1kh"),
        ]
        .concat();
        let f = frame(parse::KIND_SEQ_REQUEST, true, &auth);
        assert!(classify(&f.as_slice(), Vlan::default(), &c).is_ok());
        c.locals[0].r0kh[length - 1] = b'b';
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
        &tlv(parse::TLV_R0KH, &[b'a'; crate::proto::MAX_R0KH + 1])
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

#[test]
fn empty_peer_bssid_list_is_a_wildcard() {
    let mut c = filter();
    c.peers[0].bssid_count = 0;
    // The peer may now claim any source BSS...
    let mut f = frame(5, false, &tlv(1, b"nonce"));
    f[24..30].copy_from_slice(&[9, 9, 9, 9, 9, 9]); // RRB source BSS
    assert!(classify(&f.as_slice(), Vlan::default(), &c).is_ok());
    // ...but the Ethernet source must still be the peer's MAC.
    let mut f = frame(5, false, &tlv(1, b"nonce"));
    f[6] ^= 0x10;
    assert_eq!(
        classify(&f.as_slice(), Vlan::default(), &c).unwrap_err(),
        Counter::EtherAddress
    );
}

#[test]
fn empty_peer_list_accepts_all_senders() {
    let mut c = filter();
    c.peer_count = 0;
    // Any Ethernet source and any claimed source BSS are accepted...
    let mut f = frame(5, false, &tlv(1, b"nonce"));
    f[6..12].copy_from_slice(&[8, 8, 8, 8, 8, 8]); // Ethernet src
    f[24..30].copy_from_slice(&[9, 9, 9, 9, 9, 9]); // RRB source BSS
    assert!(classify(&f.as_slice(), Vlan::default(), &c).is_ok());
    // ...while everything else still applies: the destination BSS must still
    // be a configured local (or broadcast with the R0KH restriction).
    let mut f = frame(5, false, &tlv(1, b"nonce"));
    f[30..36].copy_from_slice(&[7, 7, 7, 7, 7, 7]); // RRB destination BSS
    assert_eq!(
        classify(&f.as_slice(), Vlan::default(), &c).unwrap_err(),
        Counter::DestinationBss
    );
}

#[test]
fn s1kh_client_mac_is_extracted_but_never_a_gate() {
    let client = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let auth = [tlv(1, b"nonce"), tlv(parse::TLV_S1KH, &client)].concat();
    let f = frame(parse::KIND_PULL, false, &auth);
    let m = classify(&f.as_slice(), Vlan::default(), &filter()).unwrap();
    assert_eq!(m.s1kh, Some(client));
    // No S1KH TLV at all: still a valid frame, just no client identity.
    let f = frame(parse::KIND_PULL, false, &tlv(1, b"nonce"));
    assert_eq!(
        classify(&f.as_slice(), Vlan::default(), &filter())
            .unwrap()
            .s1kh,
        None
    );
    // Malformed length (not ETH_ALEN): ignored, frame still accepted.
    let f = frame(parse::KIND_PULL, false, &tlv(parse::TLV_S1KH, b"short"));
    assert_eq!(
        classify(&f.as_slice(), Vlan::default(), &filter())
            .unwrap()
            .s1kh,
        None
    );
}
