//! Shared, `no_std` foundation for the RRB relay: the binary ABI exchanged
//! through BPF maps and the bounded protocol parser used identically by the
//! kernel-side eBPF action and by host-side tooling.
//!
//! Nothing here may allocate, recurse, loop unboundedly, or use floats: the
//! same code must pass the BPF verifier when compiled for bpfel-unknown-none.
#![no_std]

pub mod parse;
#[cfg(test)]
mod tests;

/// Version tag of the `Config`/`Budget` map ABI. Bumped whenever a field is
/// added, removed, or re-typed; the eBPF program refuses to act on a Config
/// whose `abi` does not match, and the loader refuses to read an old one.
///
/// History: 1 = initial; 2 = budget/rate fields; 3 = `source_ifindex`
/// replaced by the `source_ifindexes` list (multi-port support).
pub const ABI: u32 = 3;

/// Upper bound on configured peer APs. Fixed so the peer scan is a bounded
/// loop the verifier can unroll.
pub const MAX_PEERS: usize = 8;

/// Upper bound on switch-facing source interfaces (eth1, eth2, ... on the
/// UDR). Fixed so the ingress ifindex scan is a bounded loop the verifier
/// can unroll; the TC action must be attached to each listed interface.
pub const MAX_SOURCES: usize = 8;

/// Largest Ethernet frame we ever inspect, in bytes. Doubles as the bound
/// the eBPF side proves to the verifier before any packet read. RRB frames
/// are small management frames; 2048 comfortably covers any MTU on the path.
pub const MAX_FRAME: usize = 2048;

/// Upper bound on TLVs inside one RRB auth-data block. Fixed so the TLV walk
/// is a bounded loop the verifier can unroll; real 802.11r RRB frames carry
/// only a handful of elements.
pub const MAX_TLVS: usize = 16;

/// Maximum R0KH-ID length in octets, as fixed by IEEE 802.11r (an R0KH-ID is
/// 1..=48 octets). Bounds the broadcast R0KH comparison loop.
pub const MAX_R0KH: usize = 48;

/// Program completely disabled: every frame passes through untouched.
pub const MODE_OFF: u32 = 0;
/// Match and count, but never mutate or redirect: the original path is kept.
pub const MODE_OBSERVE: u32 = 1;
/// Match, count, strip the management VLAN tag, and redirect into the bridge.
pub const MODE_FORWARD: u32 = 2;

/// One peer AP allowed to source RRB traffic toward us.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Peer {
    /// MAC address the peer puts in the Ethernet source field.
    pub mac: [u8; 6],
    /// BSSID the peer must claim inside the RRB header.
    pub bssid: [u8; 6],
}

/// Runtime configuration, written by the loader into the single-entry
/// `CONFIG` ARRAY map and read by the eBPF action on every frame.
///
/// `repr(C)` plus explicit integer/byte fields only: the struct must have a
/// bit-identical layout on the host target and on bpfel-unknown-none, and
/// every bit pattern must be valid so the loader can transmute a map read.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Absolute `bpf_ktime_get_ns()` deadline; 0 means no deadline.
    pub deadline_ns: u64,
    /// Lifetime cap on redirected packets; 0 means unlimited.
    pub max_packets: u64,
    /// Must equal `ABI`, else the program treats itself as disabled.
    pub abi: u32,
    /// One of `MODE_OFF` / `MODE_OBSERVE` / `MODE_FORWARD`.
    pub mode: u32,
    /// ifindexes of the switch-facing interfaces (eth1, eth2, ... on the
    /// UDR) the TC action is attached to; frames arriving on any interface
    /// not in the first `source_count` entries are ignored.
    pub source_ifindexes: [u32; MAX_SOURCES],
    /// ifindex of the redirect target — the bridge (br0) that hostapd
    /// listens on.
    pub target_ifindex: u32,
    /// Redirects allowed per 1-second window (shared across all CPUs);
    /// always at least 1 in practice, see `Default`.
    pub packets_per_second: u32,
    /// 802.1Q VID of the management network the RRB frame must be tagged
    /// with; the tag is popped before redirecting so hostapd sees untagged.
    pub management_vlan: u16,
    /// Number of valid entries in `peers` (0..=MAX_PEERS).
    pub peer_count: u8,
    /// Number of valid bytes in `r0kh` (0..=MAX_R0KH).
    pub r0kh_len: u8,
    /// Number of valid entries in `source_ifindexes` (0..=MAX_SOURCES).
    /// 0 matches nothing: fail-closed until the loader writes real ports.
    pub source_count: u8,
    /// MAC of the redirect-target interface (br0); unicast RRB frames must
    /// be addressed here. Distinct role from `target_ifindex` (that one is
    /// where matched frames go) but the same device on the UDR.
    pub target_mac: [u8; 6],
    /// BSSID of the local AP; unicast RRB destination BSS must match it.
    pub local_bssid: [u8; 6],
    /// Expected R0KH-ID, checked only for broadcast PULL/SEQ_REQ frames.
    pub r0kh: [u8; MAX_R0KH],
    /// Peers allowed to send us RRB frames; only the first `peer_count` used.
    pub peers: [Peer; MAX_PEERS],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            deadline_ns: 0,
            max_packets: 0,
            abi: ABI,
            mode: MODE_OFF,
            source_ifindexes: [0; MAX_SOURCES],
            target_ifindex: 0,
            packets_per_second: 20, // sane floor: FT bursts are a few frames
            management_vlan: 1,     // UDR management VLAN
            peer_count: 0,
            r0kh_len: 0,
            source_count: 0,
            target_mac: [0; 6],
            local_bssid: [0; 6],
            r0kh: [0; MAX_R0KH],
            peers: [Peer::default(); MAX_PEERS],
        }
    }
}

/// Shared rate-limit/budget state, living in a single-entry ARRAY map whose
/// BTF description marks `lock` as a kernel `bpf_spin_lock`.
///
/// Userspace never touches `lock` directly; it only reads the counters with
/// the `BPF_F_LOCK` lookup flag so the kernel produces a consistent copy.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Budget {
    /// Kernel-managed spinlock word. Must be the first field and must stay
    /// 0 from userspace's point of view; the BTF type id marks it specially.
    pub lock: u32,
    /// Spare, must be 0.
    pub reserved: u32,
    /// Current 1-second window: `now_ns / 1_000_000_000`. A new window
    /// resets `used`.
    pub window: u64,
    /// Redirects already admitted in the current window.
    pub used: u64,
    /// Lifetime total of admitted redirects, checked against
    /// `Config::max_packets`.
    pub total: u64,
}

/// One slot per event in the `COUNTERS` per-CPU ARRAY map. The discriminants
/// double as map indices and must stay in sync with `COUNTER_NAMES`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    /// Every frame the action runs on.
    Seen,
    /// Config ABI/mode said "disabled".
    Disabled,
    /// `deadline_ns` passed.
    Expired,
    /// Frame too short/long to even be Ethernet + RRB.
    Length,
    /// Wrong/missing/extra VLAN tag or wrong VID.
    Vlan,
    /// Ethernet dst not us/broadcast, or src not a configured peer.
    EtherAddress,
    /// Not the RRB OUI+protocol, or unknown message type.
    OuiType,
    /// RRB source BSS does not match the peer's BSSID.
    SourceBss,
    /// RRB destination BSS is neither broadcast nor our BSSID.
    DestinationBss,
    /// Auth-data length overruns the frame.
    AuthLength,
    /// Malformed TLV stream (truncated, duplicate, or overrun).
    Tlv,
    /// Broadcast frame failing the R0KH-ID / message-type restriction.
    BroadcastScope,
    /// Passed all checks: genuinely an RRB frame for us.
    Matched,
    /// Matched while in observe mode (counted, left on the original path).
    Observed,
    /// Matched but over the per-second budget.
    RateLimited,
    /// Matched but the lifetime packet budget is exhausted.
    PacketLimit,
    /// VLAN pop or post-pop sanity check failed; frame dropped.
    VlanPopError,
    /// `bpf_redirect` issued toward the bridge.
    RedirectRequested,
    /// Matched message types 1..=5 (802.11r RRB over Ethernet).
    Pull,
    Response,
    Push,
    SeqRequest,
    SeqResponse,
}

/// Names in the exact order of `Counter` discriminants; the loader sizes the
/// COUNTERS map from this table and labels dumped values with it.
pub const COUNTER_NAMES: [&str; 23] = [
    "seen",
    "disabled",
    "expired",
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
    "packet_limit",
    "vlan_pop_error",
    "redirect_requested",
    "pull",
    "response",
    "push",
    "seq_request",
    "seq_response",
];

// ABI contract between host and BPF target: any change to these structs
// must fail the build here, never the verifier at load time.
// Config = 8+8 (limits) + 4+4 (abi/mode) + 8*4 (sources) + 4+4 (bridge,
// rate) + 2+1+1+1 (vlan + counts) + 6+6 (MACs) + 48 (r0kh) + 8*12 (peers)
// = 225 bytes of fields, padded to 232 by the 8-byte u64 alignment.
const _: () = assert!(core::mem::size_of::<Config>() == 232);
const _: () = assert!(core::mem::size_of::<Budget>() == 32);
