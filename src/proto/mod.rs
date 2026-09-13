//! RRB protocol model and validator.
//!
//! There is no kernel-side component: frames are captured passively with
//! AF_PACKET sockets, validated here against the configured [`Filter`],
//! untagged, and injected into a relay TAP whose TC `mirred` rule forwards
//! them into the bridge. This module is the frame validator ([`parse`])
//! plus the [`Counter`] vocabulary the daemon reports with.
//!
//! The parser allocates nothing and every loop is statically bounded by the
//! `MAX_*` constants — cheap to reason about and to fuzz.
pub mod parse;
#[cfg(test)]
mod tests;

/// Upper bound on configured peer APs. Fixed so the peer scan is a bounded
/// loop.
pub const MAX_PEERS: usize = 8;

/// Upper bound on local AP interfaces (BSSes) this relay serves. The UDR
/// exposes a handful of `wifiXapY` interfaces; 8 leaves generous headroom.
pub const MAX_LOCALS: usize = 8;

/// Largest Ethernet frame we ever inspect, in bytes. RRB frames are small
/// management frames; 2048 comfortably covers any MTU on the path.
pub const MAX_FRAME: usize = 2048;

/// Upper bound on TLVs inside one RRB auth-data block; real 802.11r RRB
/// frames carry only a handful of elements.
pub const MAX_TLVS: usize = 16;

/// Maximum R0KH-ID length in octets, as fixed by IEEE 802.11r (an R0KH-ID is
/// 1..=48 octets). Bounds the broadcast R0KH comparison loop.
pub const MAX_R0KH: usize = 48;

/// Upper bound on BSSIDs one peer may claim in the RRB header. A peer AP
/// typically serves several BSSes (one per `wifiXapY` interface).
pub const MAX_PEER_BSSIDS: usize = 8;

/// One peer AP allowed to source RRB traffic toward us.
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    /// MAC address the peer puts in the Ethernet source field.
    pub mac: [u8; 6],
    /// Number of valid entries in `bssids` (0..=MAX_PEER_BSSIDS). 0 is a
    /// wildcard: the peer may claim any source BSS.
    pub bssid_count: u8,
    /// BSSIDs the peer may claim inside the RRB header; only the first
    /// `bssid_count` used.
    pub bssids: [[u8; 6]; MAX_PEER_BSSIDS],
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            mac: [0; 6],
            bssid_count: 0,
            bssids: [[0; 6]; MAX_PEER_BSSIDS],
        }
    }
}

/// One local AP interface (BSS) this relay serves.
#[derive(Clone, Copy, Debug)]
pub struct Local {
    /// BSSID of the AP interface; unicast RRB destination BSS must match one
    /// of the configured locals.
    pub bssid: [u8; 6],
    /// Number of valid bytes in `r0kh` (0..=MAX_R0KH).
    pub r0kh_len: u8,
    /// R0KH-ID of this BSS. Broadcast PULL/SEQ_REQ frames must name one of
    /// the configured locals' IDs.
    pub r0kh: [u8; MAX_R0KH],
}

// Hand-written because [u8; 48] has no Default derive in std.
impl Default for Local {
    fn default() -> Self {
        Self {
            bssid: [0; 6],
            r0kh_len: 0,
            r0kh: [0; MAX_R0KH],
        }
    }
}

/// Filter identity: everything [`parse::classify`] checks a wire frame
/// against before the daemon injects it into the TAP.
#[derive(Clone, Debug)]
pub struct Filter {
    /// 802.1Q VID of the management network the RRB frame must be tagged
    /// with on the wire.
    pub management_vlan: u16,
    /// Number of valid entries in `peers` (0..=MAX_PEERS). 0 is a wildcard:
    /// any sender is accepted as a peer.
    pub peer_count: u8,
    /// Number of valid entries in `locals` (0..=MAX_LOCALS). 0 matches
    /// nothing: fail-closed until real BSSes are configured.
    pub local_count: u8,
    /// MAC of the local bridge; unicast RRB frames must be addressed here.
    pub target_mac: [u8; 6],
    /// Local BSSes we serve; only the first `local_count` used.
    pub locals: [Local; MAX_LOCALS],
    /// Peers allowed to send us RRB frames; only the first `peer_count` used.
    pub peers: [Peer; MAX_PEERS],
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            management_vlan: 1, // UDR management VLAN
            peer_count: 0,
            local_count: 0,
            target_mac: [0; 6],
            locals: [Local::default(); MAX_LOCALS],
            peers: [Peer::default(); MAX_PEERS],
        }
    }
}

/// Event vocabulary for daemon statistics. Rejection discriminants are
/// returned by [`parse::classify`] 1:1; the rest the daemon increments
/// itself. Must stay in sync with `COUNTER_NAMES`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    /// Every frame the AF_PACKET sockets delivered (post cBPF filter).
    Seen,
    /// Frame too short/long to even be Ethernet + RRB.
    Length,
    /// Wrong/missing/extra VLAN tag or wrong VID.
    Vlan,
    /// Ethernet dst not us/broadcast, or src not a configured peer.
    EtherAddress,
    /// Not the RRB OUI+protocol, or unknown message type.
    OuiType,
    /// RRB source BSS matches none of the peer's BSSIDs.
    SourceBss,
    /// RRB destination BSS is neither broadcast nor a local BSS.
    DestinationBss,
    /// Auth-data length overruns the frame.
    AuthLength,
    /// Malformed TLV stream (truncated, duplicate, or overrun).
    Tlv,
    /// Broadcast frame failing the R0KH-ID / message-type restriction.
    BroadcastScope,
    /// Passed all checks: genuinely an RRB frame for us.
    Matched,
    /// Matched while in observe mode (counted, not relayed).
    Observed,
    /// Matched but over the per-second budget.
    RateLimited,
    /// Frame written to the relay TAP.
    Injected,
    /// TAP write failed.
    InjectError,
    /// Matched message types 1..=5 (802.11r RRB over Ethernet).
    Pull,
    Response,
    Push,
    SeqRequest,
    SeqResponse,
}

/// Names in the exact order of `Counter` discriminants.
pub const COUNTER_NAMES: [&str; 20] = [
    "seen",
    "reject_length",
    "reject_vlan",
    "reject_ether_address",
    "reject_oui_or_type",
    "reject_source_bss",
    "reject_destination_bss",
    "reject_auth_length",
    "reject_tlv",
    "reject_broadcast_scope",
    "matched",
    "observed",
    "rate_limited",
    "injected",
    "inject_error",
    "pull",
    "response",
    "push",
    "seq_request",
    "seq_response",
];
