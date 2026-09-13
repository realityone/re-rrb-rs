//! eBPF TC action that relays UniFi 802.11r RRB frames.
//!
//! Problem from first principles: the switch delivers RRB frames (EtherType
//! 0x88B7) to the switch-facing ports (eth1, eth2, ...), but hostapd listens
//! on the bridge (br0), and nothing in the kernel forwards L2 frames between
//! the two. This program hangs on each configured port's TC ingress as a BPF
//! *action*; for every
//! frame it re-validates identity from scratch, and for genuine RRB frames
//! it pops the inner management VLAN tag and redirects the *original* skb
//! into br0's RX path, where hostapd sees it as normally received. No clone,
//! no intermediate interface, no daemon: once loaded, the kernel keeps
//! everything; userspace exits.
//!
//! Target kernel is Linux 5.4 (UDR firmware): only helpers available there
//! may be used, and the program must load as SCHED_ACT because the kernel
//! has NET_ACT_BPF but no NET_CLS_BPF.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{__sk_buff, bpf_spin_lock as SpinLock},
    helpers::{
        bpf_ktime_get_ns, bpf_redirect, bpf_skb_load_bytes, bpf_skb_vlan_pop, bpf_spin_lock,
        bpf_spin_unlock,
    },
    macros::{classifier, map},
    maps::{Array, PerCpuArray},
    programs::TcContext,
};
use rrb_common::{
    ABI, Budget, COUNTER_NAMES, Config, Counter, MAX_FRAME, MAX_SOURCES, MODE_FORWARD,
    MODE_OBSERVE, MODE_OFF,
    parse::{self, ReadFrame, Vlan},
};

/// TC_ACT_UNSPEC: "no opinion". The frame continues with the pipeline's
/// default action, i.e. it keeps its original path as if we never ran.
const CONTINUE: i32 = -1;
/// TC_ACT_SHOT: drop the frame. Used only after we have already mutated it;
/// returning a modified frame to the original path would corrupt eth2's
/// stream, so a failed mutation must kill the frame instead.
const DROP: i32 = 2;
/// BPF_F_INGRESS: redirect to the *ingress* (RX) side of the target
/// interface, so br0 and hostapd process the frame as freshly received.
const REDIRECT_INGRESS: u64 = 1;

/// Nanoseconds in one second: the rate-limit window granularity.
const NS_PER_SECOND: u64 = 1_000_000_000;

/// Single-entry map holding the loader-written `Config`. Entry 0 only.
#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
/// Per-CPU event counters, indexed by `Counter` discriminant. Per-CPU so
/// increments need no locking (TC runs with migration disabled).
#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(COUNTER_NAMES.len() as u32, 0);
/// Single-entry shared rate-limit state, guarded by a kernel bpf_spin_lock
/// declared through the loader-supplied BTF.
#[map]
static BUDGET: Array<Budget> = Array::with_max_entries(1, 0);

/// `ReadFrame` over the kernel skb: all reads go through
/// `bpf_skb_load_bytes`, which also works on non-linear (multi-fragment)
/// skbs, unlike direct packet data access.
struct Packet(*mut __sk_buff);
impl ReadFrame for Packet {
    #[inline(always)]
    fn len(&self) -> usize {
        unsafe { (*self.0).len as usize }
    }
    #[inline(always)]
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        // Refuse anything beyond the parser's own frame bound: keeps every
        // offset provably small for the verifier and never touches memory.
        if offset > MAX_FRAME || offset + N > self.len() {
            return None;
        }
        let mut out = [0u8; N];
        let rc = unsafe {
            bpf_skb_load_bytes(
                self.0.cast(),
                offset as u32,
                out.as_mut_ptr().cast(),
                N as u32,
            )
        };
        if rc == 0 { Some(out) } else { None }
    }
}

#[inline(always)]
fn count(counter: Counter) {
    if let Some(p) = COUNTERS.get_ptr_mut(counter as u32) {
        // TC runs with migration disabled, so this CPU is the only writer to
        // this slot; a plain increment cannot race.
        unsafe {
            *p += 1;
        }
    }
}

/// Lift the skb's VLAN metadata into the parser's view. `vlan_proto` is
/// big-endian in `__sk_buff`; the parser works in host byte order.
#[inline(always)]
fn vlan(skb: *mut __sk_buff) -> Vlan {
    unsafe {
        Vlan {
            present: (*skb).vlan_present != 0,
            proto: u16::from_be((*skb).vlan_proto as u16),
            tci: (*skb).vlan_tci as u16,
        }
    }
}

/// Is the program currently allowed to act at all?
#[inline(always)]
fn active(c: &Config, now: u64) -> bool {
    if c.abi != ABI || c.mode == MODE_OFF {
        count(Counter::Disabled);
        return false;
    }
    if c.deadline_ns != 0 && now >= c.deadline_ns {
        count(Counter::Expired);
        return false;
    }
    c.mode == MODE_OBSERVE || c.mode == MODE_FORWARD
}

/// Fixed-window (not token bucket) rate + lifetime limiter, shared by all
/// CPUs. The bpf_spin_lock critical section may contain field accesses
/// only: no helper calls, no tail calls, no early returns while locked, or
/// the verifier rejects the program.
#[inline(always)]
fn admit(c: &Config, now: u64) -> Result<(), Counter> {
    let p = BUDGET.get_ptr_mut(0).ok_or(Counter::PacketLimit)?;
    let window = now / NS_PER_SECOND;
    let mut result = Ok(());
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*p).lock).cast::<SpinLock>());
        if (*p).window != window {
            (*p).window = window;
            (*p).used = 0;
        }
        if c.max_packets != 0 && (*p).total >= c.max_packets {
            result = Err(Counter::PacketLimit);
        } else if (*p).used >= u64::from(c.packets_per_second) {
            result = Err(Counter::RateLimited);
        } else {
            (*p).used += 1;
            (*p).total += 1;
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!((*p).lock).cast::<SpinLock>());
    }
    result
}

/// Does the arrival ifindex belong to a configured switch-facing port?
/// Bounded scan over `MAX_SOURCES` (not `source_count`) so the verifier sees
/// a statically bounded loop; the same program binary serves every port, so
/// one load covers eth1, eth2, ... without per-interface programs.
#[inline(always)]
fn on_source_port(c: &Config, ifindex: u32) -> bool {
    let mut found = false;
    for i in 0..MAX_SOURCES {
        if i < c.source_count as usize && c.source_ifindexes[i] == ifindex {
            found = true;
        }
    }
    found
}

// The `classifier` macro supplies a TC-compatible ELF section and context
// ONLY. The loader explicitly loads this as BPF_PROG_TYPE_SCHED_ACT (4),
// never SCHED_CLS (3): the UDR kernel lacks CONFIG_NET_CLS_BPF.
#[classifier]
pub fn rrb_redirect(ctx: TcContext) -> i32 {
    count(Counter::Seen);
    let Some(c) = CONFIG.get(0) else {
        return CONTINUE;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    // Wrong ABI/mode, expired, or not arriving on a configured port: not
    // our business, leave the frame alone.
    if !active(c, now) || !on_source_port(c, unsafe { (*ctx.skb.skb).ifindex }) {
        return CONTINUE;
    }
    let matched = match parse::classify(&Packet(ctx.skb.skb), vlan(ctx.skb.skb), c) {
        Ok(m) => m,
        Err(reason) => {
            count(reason);
            return CONTINUE;
        }
    };
    count(Counter::Matched);
    count(match matched.kind {
        parse::KIND_PULL => Counter::Pull,
        parse::KIND_RESPONSE => Counter::Response,
        parse::KIND_PUSH => Counter::Push,
        parse::KIND_SEQ_REQUEST => Counter::SeqRequest,
        _ => Counter::SeqResponse,
    });
    if c.mode == MODE_OBSERVE {
        count(Counter::Observed);
        return CONTINUE;
    }
    if let Err(reason) = admit(c, now) {
        count(reason);
        return CONTINUE;
    }
    // Re-check liveness with a fresh clock: the frame may have queued behind
    // the budget lock past the deadline, and mode may have been rewritten.
    if !active(c, unsafe { bpf_ktime_get_ns() }) || c.mode != MODE_FORWARD {
        return CONTINUE;
    }
    // Scope and limits passed. Transfer the original RRB frame into br0 RX;
    // no clone or intermediate device. From the first mutation attempt on,
    // failures drop this matched frame rather than returning a modified one
    // to eth2's path.
    if unsafe { bpf_skb_vlan_pop(ctx.skb.skb.cast()) } != 0 {
        count(Counter::VlanPopError);
        return DROP;
    }
    // Sanity: after popping one tag, the EtherType at offset 12 must be RRB.
    // If the frame had no inline tag to pop or popped the wrong one, this
    // catches it before we hand garbage to the bridge.
    if Packet(ctx.skb.skb).read::<2>(parse::ETH_TYPE_OFFSET) != Some(parse::ETH_P_RRB.to_be_bytes())
    {
        count(Counter::VlanPopError);
        return DROP;
    }
    count(Counter::RedirectRequested);
    unsafe { bpf_redirect(c.target_ifindex, REDIRECT_INGRESS) as i32 }
}

// The kernel reads this section to decide whether GPL-only helpers are
// allowed. (The helpers used here are not GPL-only, but the string must be
// present and valid regardless.)
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
