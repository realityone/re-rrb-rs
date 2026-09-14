//! Passive AF_PACKET capture on the switch-facing ports.
//!
//! This is the safe side of the relay: a packet socket only *observes* the
//! wire (exactly what tcpdump does) and never changes how the kernel
//! processes the original frame. A classic BPF socket filter keeps every
//! non-RRB frame from ever waking userspace.
use crate::proto::parse::{self, Vlan};
use anyhow::{Context, Result, bail};
use std::{
    ffi::CString,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::io::unix::AsyncFd;

// --- classic BPF (cBPF) socket filter --------------------------------------
// The 32-bit instruction set SO_ATTACH_FILTER has accepted since Linux 2.1.
// Only the three opcodes used below are named.
/// BPF_LD|BPF_H|BPF_ABS: load the big-endian u16 at an absolute frame offset.
const BPF_LD_H_ABS: u16 = 0x28;
/// BPF_JMP|BPF_JEQ|BPF_K: skip jt/jf instructions on equal/not-equal.
const BPF_JEQ_K: u16 = 0x15;
/// BPF_RET|BPF_K: terminate, returning the constant (nonzero = keep bytes).
const BPF_RET_K: u16 = 0x06;

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// `struct sock_fprog` (linux/filter.h). repr(C) inserts the pointer
/// alignment padding after `len` automatically.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Accept only RRB candidates: EtherType 0x88B7, either bare at offset 12 or
/// behind one 802.1Q tag (TPID 0x8100 at 12, EtherType at 16). Everything
/// else is dropped in the kernel and never reaches userspace.
const SOCKET_FILTER: [SockFilter; 7] = [
    // 0: A = u16[12] (EtherType, or TPID when tagged)
    SockFilter {
        code: BPF_LD_H_ABS,
        jt: 0,
        jf: 0,
        k: 12,
    },
    // 1: A == 0x8100? -> 2 (tagged path) : 4 (bare path)
    SockFilter {
        code: BPF_JEQ_K,
        jt: 0,
        jf: 2,
        k: 0x8100,
    },
    // 2: A = u16[16] (inner EtherType behind the tag)
    SockFilter {
        code: BPF_LD_H_ABS,
        jt: 0,
        jf: 0,
        k: 16,
    },
    // 3: A == 0x88B7? -> 5 (accept) : 6 (drop)
    SockFilter {
        code: BPF_JEQ_K,
        jt: 1,
        jf: 2,
        k: 0x88b7,
    },
    // 4: A == 0x88B7? -> 5 (accept) : 6 (drop)
    SockFilter {
        code: BPF_JEQ_K,
        jt: 0,
        jf: 1,
        k: 0x88b7,
    },
    // 5: accept up to 65535 bytes
    SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: 0x0000_ffff,
    },
    // 6: drop
    SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: 0,
    },
];

// --- PACKET_AUXDATA (VLAN offload metadata) ---------------------------------
// tpacket_auxdata.tp_status bits (linux/if_packet.h):
/// A VLAN tag was stripped by hardware/driver offload into the auxdata.
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
/// tp_vlan_tpid carries the real TPID. Only set since Linux 5.14; the UDR's
/// 5.4 kernel never sets it, and the management tag there is always 0x8100.
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;

/// `struct tpacket_auxdata` (linux/if_packet.h): the control-message payload
/// PACKET_AUXDATA delivers alongside each frame.
#[repr(C)]
struct TpacketAuxdata {
    status: u32,
    len: u32,
    snaplen: u32,
    mac: u16,
    net: u16,
    vlan_tci: u16,
    vlan_tpid: u16,
}

/// Kernel packet direction marker (linux/if_packet.h): frames the host
/// itself transmitted. Packet sockets see egress too, and this host's own
/// hostapd emits RRB onto the segment — those must not loop back through
/// the relay.
const PACKET_OUTGOING: u8 = 4;

/// One non-blocking packet socket bound to a single interface, wrapped for
/// tokio readiness-based I/O.
pub struct PacketSocket {
    fd: AsyncFd<OwnedFd>,
    /// Interface name, kept for logging.
    pub name: String,
}

impl PacketSocket {
    /// Configure a packet socket, then bind it to start capture on `name`.
    pub fn open(name: &str) -> Result<Self> {
        let ifindex = ifindex(name).context("resolve source interface")?;
        // Protocol 0 keeps capture inactive until the filter and metadata
        // options are installed; bind below selects the interface and protocol.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("socket(AF_PACKET)");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let prog = SockFprog {
            len: SOCKET_FILTER.len() as u16,
            filter: SOCKET_FILTER.as_ptr(),
        };
        // SOL_SOCKET(1) / SO_ATTACH_FILTER(26).
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&raw const prog).cast::<libc::c_void>(),
                size_of::<SockFprog>() as u32,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("attach socket filter");
        }
        // SOL_PACKET(263) / PACKET_AUXDATA(8): deliver VLAN-offload metadata
        // with each frame, so a hardware-stripped tag is still visible.
        let one: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_AUXDATA,
                (&raw const one).cast::<libc::c_void>(),
                size_of::<libc::c_int>() as u32,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("enable PACKET_AUXDATA");
        }
        // Skip outgoing traffic before the kernel clones or filters it for
        // this socket. Keep the recvmsg direction check as a defensive guard.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_IGNORE_OUTGOING,
                (&raw const one).cast::<libc::c_void>(),
                size_of::<libc::c_int>() as u32,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("enable PACKET_IGNORE_OUTGOING");
        }
        // Binding with ETH_P_ALL (in network byte order) activates capture
        // only on this interface; the cBPF filter narrows the EtherTypes.
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: u16::to_be(libc::ETH_P_ALL as u16),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("bind packet socket");
        }
        Ok(Self {
            fd: AsyncFd::new(fd).context("register packet socket with tokio")?,
            name: name.to_string(),
        })
    }

    /// Receive one frame plus its VLAN view. Frames transmitted by this host
    /// (PACKET_OUTGOING) are skipped.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, Vlan)> {
        loop {
            let mut guard = self.fd.readable().await?;
            let outcome = guard.try_io(|inner| recvmsg(inner.get_ref().as_raw_fd(), buf));
            match outcome {
                Ok(Ok(Some(v))) => return Ok(v),
                Ok(Ok(None)) => continue, // PACKET_OUTGOING: poll again
                Ok(Err(e)) => bail!("recvmsg on {}: {e}", self.name),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Blocking-free recvmsg; `Ok(None)` means "skip this frame" (egress echo).
fn recvmsg(fd: i32, buf: &mut [u8]) -> std::io::Result<Option<(usize, Vlan)>> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // One PACKET_AUXDATA control message fits comfortably in 64 bytes.
    let mut control = [0u8; 64];
    let mut name = MaybeUninit::<libc::sockaddr_ll>::zeroed();
    let mut msg: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_name = name.as_mut_ptr().cast();
    msg.msg_namelen = size_of::<libc::sockaddr_ll>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    // glibc uses size_t here, musl uses socklen_t; 64 bytes fits either.
    msg.msg_controllen = control.len() as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { name.assume_init() }.sll_pkttype == PACKET_OUTGOING {
        return Ok(None);
    }
    let mut vlan = Vlan::default();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_PACKET && header.cmsg_type == libc::PACKET_AUXDATA {
            let aux = unsafe { &*(libc::CMSG_DATA(cmsg).cast::<TpacketAuxdata>()) };
            if aux.status & TP_STATUS_VLAN_VALID != 0 {
                vlan.present = true;
                vlan.tci = aux.vlan_tci;
                vlan.proto = if aux.status & TP_STATUS_VLAN_TPID_VALID != 0 {
                    aux.vlan_tpid
                } else {
                    parse::TPID_8021Q
                };
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok(Some((n as usize, vlan)))
}

/// ifindex of an interface name, via libc (getifaddrs-free).
fn ifindex(name: &str) -> Result<u32> {
    let cname = CString::new(name)?;
    let n = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if n == 0 {
        bail!("interface {name} not found");
    }
    Ok(n)
}
