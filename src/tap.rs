//! The relay TAP device and the TC mirred rule that does the actual forward.
//!
//! Trust model: this TAP has exactly one writer — this process. It is
//! non-persistent, so when the process exits (cleanly or via SIGKILL) the
//! kernel destroys the interface and every TC rule on it. The mirred rule
//! is therefore as self-cleaning as the process itself.
use anyhow::{Context, Result};
use std::process::Command;
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

/// Conventional handle of the ingress qdisc ("ffff:" == 0xffff).
const INGRESS_HANDLE: &str = "ffff:";

/// Create the relay TAP, silence kernel chatter on it, bring it up, and
/// install the forwarding rule:
///
/// ```text
/// tc qdisc  add dev <tap> handle ffff: ingress
/// tc filter add dev <tap> parent ffff: protocol 0x88b7 pref <pref> \
///     u32 match u32 0 0 action mirred ingress redirect dev <target>
/// ```
///
/// - `protocol 0x88b7` is the kernel-side gate: TAP frames get their
///   skb->protocol from the frame's EtherType, so only RRB frames reach the
///   action at all.
/// - `u32 match u32 0 0` matches every frame the protocol gate let through.
/// - `mirred ingress redirect` is exactly `bpf_redirect(target,
///   BPF_F_INGRESS)` without a BPF program: the frame appears on the
///   target's RX path as if the NIC had received it, which is what hostapd
///   (listening on br0) needs.
pub async fn create_relay(name: &str, target: &str, pref: u16) -> Result<RelayTap> {
    let dev = DeviceBuilder::new()
        .name(name)
        .layer(Layer::L2) // TAP: full Ethernet frames, no packet-information header
        .build_async()
        .context("create TAP device (needs root / CAP_NET_ADMIN)")?;
    let actual = dev.name().context("read TAP name")?;
    // Keep kernel-originated traffic (IPv6 router solicitations, etc.) off
    // the mirred path. Belt and braces: the protocol-0x88b7 gate already
    // drops it, but disabling IPv6 removes the noise at the source.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{actual}/disable_ipv6"),
        "1",
    );
    set_up(&actual)?;
    tc_attach(&actual, target, pref)?;
    let ifindex = dev.if_index().context("TAP ifindex")?;
    Ok(RelayTap {
        dev,
        name: actual,
        ifindex,
    })
}

pub struct RelayTap {
    pub dev: AsyncDevice,
    pub name: String,
    pub ifindex: u32,
}

impl RelayTap {
    /// Inject one already-validated, untagged frame.
    pub async fn inject(&self, frame: &[u8]) -> std::io::Result<()> {
        self.dev.send(frame).await?;
        Ok(())
    }
}

/// Remove leftovers of a previous run identified by TAP name: our filter
/// priority, the ingress qdisc, and the device itself (in case one was ever
/// made persistent).
pub async fn destroy(name: &str, pref: u16) -> Result<()> {
    let pref = pref.to_string();
    let _ = run(
        "tc",
        &[
            "filter",
            "del",
            "dev",
            name,
            "parent",
            INGRESS_HANDLE,
            "pref",
            &pref,
        ],
    );
    let _ = run("tc", &["qdisc", "del", "dev", name, "ingress"]);
    if std::path::Path::new(&format!("/sys/class/net/{name}")).exists() {
        run("ip", &["link", "del", "dev", name]).context("delete leftover TAP")?;
    }
    Ok(())
}

/// Kernel-side packet/byte counters of the mirred action, for cross-checking
/// against the daemon's own statistics.
pub async fn action_stats(name: &str) -> Result<String> {
    run(
        "tc",
        &[
            "-s",
            "filter",
            "show",
            "dev",
            name,
            "parent",
            INGRESS_HANDLE,
        ],
    )
}

fn tc_attach(tap: &str, target: &str, pref: u16) -> Result<()> {
    run(
        "tc",
        &[
            "qdisc",
            "add",
            "dev",
            tap,
            "handle",
            INGRESS_HANDLE,
            "ingress",
        ],
    )
    .context("add ingress qdisc")?;
    run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            tap,
            "parent",
            INGRESS_HANDLE,
            "protocol",
            "0x88b7",
            "pref",
            &pref.to_string(),
            "u32",
            "match",
            "u32",
            "0",
            "0",
            "action",
            "mirred",
            "ingress",
            "redirect",
            "dev",
            target,
        ],
    )
    .context("add mirred redirect rule")?;
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    // Arguments never pass through a shell.
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("execute {program}"))?;
    anyhow::ensure!(
        out.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8(out.stdout)?)
}

/// Bring the interface up via SIOCSIFFLAGS. tun-rs only sets addresses/routes
/// when configured; we want a bare L2 device, so we flip the flag ourselves.
fn set_up(name: &str) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket for ifflags");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // struct ifreq: 16-byte name (IFNAMSIZ) followed by a union whose flags
    // member sits at offset 16.
    let mut req = [0u8; 40];
    let bytes = name.as_bytes();
    anyhow::ensure!(bytes.len() < 16, "interface name too long");
    req[..bytes.len()].copy_from_slice(bytes);
    // SIOCGIFFLAGS = 0x8913, SIOCSIFFLAGS = 0x8914 (linux/sockios.h).
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0x8913, req.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCGIFFLAGS");
    }
    let flags = u16::from_ne_bytes([req[16], req[17]]) | libc::IFF_UP as u16;
    req[16..18].copy_from_slice(&flags.to_ne_bytes());
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0x8914, req.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCSIFFLAGS");
    }
    Ok(())
}
