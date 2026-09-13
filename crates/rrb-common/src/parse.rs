//! Bounded, allocation-free parser for UniFi-style 802.11r RRB frames,
//! shared verbatim by the eBPF action and by host-side offline inspection.
//!
//! Frame layout expected at the switch-facing TC ingress hook:
//!
//! ```text
//!  0        6        12   14           18
//!  | dst MAC | src MAC | TPID | TCI | EtherType | RRB header | auth TLVs | trailer |
//!                         `-- 802.1Q tag (4 bytes, optional, see below)
//! ```
//!
//! The outer service VLAN has already selected the interface by the time the
//! frame reaches us; exactly one inner 802.1Q management tag must remain,
//! either as skb metadata (`vlan_present`) or inline in the frame.
//!
//! Every reader must return `None` on any out-of-bounds access: the BPF
//! verifier has to see that all reads are guarded.
use crate::{Config, Counter, MAX_FRAME, MAX_PEERS, MAX_R0KH, MAX_TLVS};

/// EtherType assigned to 802.11r RRB (Fast BSS Transition over the
/// distribution system): "RRB" frames between APs.
pub const ETH_P_RRB: u16 = 0x88b7;

/// 802.1Q tag protocol identifier.
pub const TPID_8021Q: u16 = 0x8100;

/// Mask extracting the 12-bit VLAN ID out of a 16-bit TCI
/// (TCI = PCP[15:13] | DEI[12] | VID[11:0]).
pub const TCI_VID_MASK: u16 = 0x0fff;

/// Length of the Ethernet II header up to and including the EtherType.
pub const ETH_HEADER_LEN: usize = 14;

/// Offset of the EtherType/TPID field inside an Ethernet II header.
pub const ETH_TYPE_OFFSET: usize = 12;

/// Bytes added by one inline 802.1Q tag (TPID + TCI).
pub const VLAN_TAG_LEN: usize = 4;

/// RRB fixed header length: 5-byte protocol selector, 1-byte message type,
/// 6-byte source BSS, 6-byte destination BSS, 2-byte auth-data length.
pub const RRB_HEADER_LEN: usize = 20;

/// RRB protocol selector that must prefix every frame body: the 3-octet OUI
/// 00:13:74 followed by the two protocol octets 00 01.
pub const RRB_SELECTOR: [u8; 5] = [0x00, 0x13, 0x74, 0x00, 0x01];

/// RRB message types (the byte right after the selector).
pub const KIND_PULL: u8 = 1;
pub const KIND_RESPONSE: u8 = 2;
pub const KIND_PUSH: u8 = 3;
pub const KIND_SEQ_REQUEST: u8 = 4;
pub const KIND_SEQ_RESPONSE: u8 = 5;

/// TLV tag carrying the R0KH-ID inside the auth-data block.
pub const TLV_R0KH: u16 = 4;

/// Fixed header length of one TLV: 2-byte tag + 2-byte size, both
/// little-endian per the RRB-over-Ethernet wire format.
pub const TLV_HEADER_LEN: usize = 4;

/// Trailing authenticator appended after the auth-data block; its length is
/// part of the frame geometry check but its contents are not validated here
/// (hostapd remains the cryptographic authority).
pub const TRAILER_LEN: usize = 16;

/// Broadcast destination, written longhand where comparisons happen.
pub const BROADCAST: [u8; 6] = [255; 6];

/// Byte-slice view of a frame, so the same parser runs on a userspace buffer
/// and (via the eBPF impl) on `bpf_skb_load_bytes` reads.
pub trait ReadFrame {
    fn len(&self) -> usize;
    /// Read exactly `N` bytes at `offset`, or `None` if out of bounds.
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReadFrame for &[u8] {
    #[inline(always)]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
    #[inline(always)]
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        self.get(offset..offset.checked_add(N)?)?.try_into().ok()
    }
}

/// How the management VLAN tag reached us.
#[derive(Clone, Copy, Default)]
pub struct Vlan {
    /// True when the kernel already parsed the tag into skb metadata
    /// (`__sk_buff.vlan_present`); the 4 tag bytes are then NOT in the frame.
    pub present: bool,
    /// Tagged protocol, host byte order; converted from
    /// `__sk_buff.vlan_proto` by the caller. Only meaningful if `present`.
    pub proto: u16,
    /// Full TCI (PCP|DEI|VID), host byte order; only the VID is checked.
    pub tci: u16,
}

/// A frame that passed every check.
#[derive(Clone, Copy, Debug)]
pub struct Match {
    /// RRB message type, one of `KIND_*` (1..=5).
    pub kind: u8,
    /// Offset of the RRB header: 14 with a metadata tag, 18 with an inline
    /// tag. Kept so callers can locate the body without re-parsing VLANs.
    pub body_offset: usize,
}

/// Full ingress gate: geometry, VLAN scope, Ethernet addresses, RRB header,
/// TLV stream, and broadcast restrictions, in that order.
///
/// Errors map 1:1 to `Counter` rejection slots so the kernel side can count
/// why a frame was left alone.
#[inline(always)]
pub fn classify<R: ReadFrame>(r: &R, vlan: Vlan, c: &Config) -> Result<Match, Counter> {
    if r.len() < ETH_HEADER_LEN || r.len() > MAX_FRAME {
        return Err(Counter::Length);
    }
    let proto = u16::from_be_bytes(r.read::<2>(ETH_TYPE_OFFSET).ok_or(Counter::Length)?);
    let body = if vlan.present {
        // Tag lives in skb metadata: the on-wire EtherType must already be
        // RRB, and the metadata tag must be our management VLAN.
        if vlan.proto != TPID_8021Q
            || vlan.tci & TCI_VID_MASK != c.management_vlan
            || proto != ETH_P_RRB
        {
            return Err(Counter::Vlan);
        }
        ETH_HEADER_LEN
    } else {
        // Tag must be inline right after the Ethernet header: TPID 0x8100,
        // our management VID, then the RRB EtherType. PCP/DEI are masked
        // out and ignored on purpose.
        let tag = r.read::<4>(ETH_HEADER_LEN).ok_or(Counter::Vlan)?;
        if proto != TPID_8021Q
            || u16::from_be_bytes([tag[0], tag[1]]) & TCI_VID_MASK != c.management_vlan
            || tag[2..4] != ETH_P_RRB.to_be_bytes()
        {
            return Err(Counter::Vlan);
        }
        ETH_HEADER_LEN + VLAN_TAG_LEN
    };
    parse_rrb(r, body, c)
}

/// Validate the RRB body starting at `body` against the configured identity.
#[inline(always)]
pub fn parse_rrb<R: ReadFrame>(r: &R, body: usize, c: &Config) -> Result<Match, Counter> {
    let dst = r.read::<6>(0).ok_or(Counter::Length)?;
    let src = r.read::<6>(6).ok_or(Counter::Length)?;
    // Addressed to our bridge, or broadcast (PULL/SEQ_REQ discovery).
    if dst != c.target_mac && dst != BROADCAST {
        return Err(Counter::EtherAddress);
    }
    // Bounded scan over configured peers; the loop bound is MAX_PEERS, not
    // peer_count, so the verifier sees a statically bounded loop.
    let mut expected_bss = [0u8; 6];
    let mut peer_found = false;
    for i in 0..MAX_PEERS {
        if i < c.peer_count as usize && c.peers[i].mac == src {
            expected_bss = c.peers[i].bssid;
            peer_found = true;
        }
    }
    if !peer_found {
        return Err(Counter::EtherAddress);
    }

    let header = r.read::<RRB_HEADER_LEN>(body).ok_or(Counter::Length)?;
    // header[0..5]: OUI 00:13:74 + protocol 00 01; header[5]: message type.
    if header[..5] != RRB_SELECTOR || header[5] < KIND_PULL || header[5] > KIND_SEQ_RESPONSE {
        return Err(Counter::OuiType);
    }
    // The BSS the frame claims to originate from must be the peer's own.
    if header[6..12] != expected_bss {
        return Err(Counter::SourceBss);
    }
    let broadcast = header[12..18] == BROADCAST;
    if !broadcast && header[12..18] != c.local_bssid {
        return Err(Counter::DestinationBss);
    }
    // Auth-data length is little-endian on the wire.
    let alen = u16::from_le_bytes([header[18], header[19]]) as usize;
    let end = body + RRB_HEADER_LEN + alen;
    if end + TRAILER_LEN > r.len() {
        return Err(Counter::AuthLength);
    }

    // Walk TLVs with a fixed iteration bound; duplicates are rejected so one
    // TLV cannot smuggle conflicting values past a naive first-match reader.
    let mut pos = body + RRB_HEADER_LEN;
    let mut tags = [0u16; MAX_TLVS];
    let mut r0kh_position = 0;
    let mut r0kh_size = 0;
    for i in 0..MAX_TLVS {
        if pos == end {
            break;
        }
        if pos + TLV_HEADER_LEN > end {
            return Err(Counter::Tlv);
        }
        let tlv = r.read::<4>(pos).ok_or(Counter::Tlv)?;
        let tag = u16::from_le_bytes([tlv[0], tlv[1]]);
        let size = u16::from_le_bytes([tlv[2], tlv[3]]) as usize;
        for (j, previous) in tags.iter().enumerate() {
            if j < i && *previous == tag {
                return Err(Counter::Tlv);
            }
        }
        tags[i] = tag;
        pos += TLV_HEADER_LEN;
        if pos + size > end {
            return Err(Counter::Tlv);
        }
        if tag == TLV_R0KH {
            r0kh_position = pos;
            r0kh_size = size;
        }
        pos += size;
    }
    if pos != end {
        return Err(Counter::Tlv);
    }

    // Broadcast frames are how an intruder would spray RRB onto the segment,
    // so they face an extra restriction: only PULL and SEQ_REQ may be
    // broadcast, and they must name exactly our R0KH-ID. The comparison runs
    // once, after TLV validation, to avoid a nested variable-length loop
    // that would explode verifier path count.
    if broadcast {
        if (header[5] != KIND_PULL && header[5] != KIND_SEQ_REQUEST)
            || r0kh_size == 0
            || r0kh_size > MAX_R0KH
            || r0kh_size != c.r0kh_len as usize
        {
            return Err(Counter::BroadcastScope);
        }
        for j in 0..MAX_R0KH {
            if j == r0kh_size {
                break;
            }
            if r.read::<1>(r0kh_position + j).ok_or(Counter::Tlv)?[0] != c.r0kh[j] {
                return Err(Counter::BroadcastScope);
            }
        }
    }
    Ok(Match {
        kind: header[5],
        body_offset: body,
    })
}
