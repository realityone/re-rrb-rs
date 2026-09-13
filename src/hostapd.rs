//! hostapd control-interface client (Linux only at runtime).
//!
//! hostapd exposes one unix datagram socket per managed interface under
//! `/run/hostapd/<ifname>`. The protocol is dead simple: send a command
//! string, receive one datagram back. We use `GET_CONFIG`, which answers
//! with `key=value` lines. The key we care about is `bssid` — UniFi's
//! hostapd does not report `nas_identifier` here, but that is fine: on
//! UniFi the R0KH-ID is the BSSID itself (hex without colons), so the BSSID
//! is all we need.
//!
//! The client socket is never bound explicitly: on Linux an unbound unix
//! datagram socket is autobound to an abstract address on connect (unix(7)),
//! which is all hostapd needs to address its reply — no filesystem
//! bookkeeping on our side.
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

/// Directory hostapd places its control sockets in (hostapd default and
/// UniFi's layout alike).
pub const SOCKET_DIR: &str = "/run/hostapd";

/// Only wifi* sockets are considered — the directory may also hold sockets
/// for unrelated hostapd instances.
pub const SOCKET_PREFIX: &str = "wifi";

/// hostapd is local and answers instantly; one second only guards against a
/// stuck daemon.
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// GET_CONFIG answers comfortably within one datagram.
const REPLY_BUF: usize = 8192;

/// Parsed `GET_CONFIG` reply.
pub type Config = BTreeMap<String, String>;

/// One query-reply exchange with the control socket of `ifname`.
pub fn get_config(ifname: &str) -> Result<Config> {
    let sock = UnixDatagram::unbound().context("create client socket")?;
    sock.set_read_timeout(Some(REPLY_TIMEOUT))?;
    sock.connect(format!("{SOCKET_DIR}/{ifname}"))
        .with_context(|| format!("connect hostapd socket for {ifname}"))?;
    sock.send(b"GET_CONFIG").context("send GET_CONFIG")?;
    let mut buf = [0u8; REPLY_BUF];
    let n = sock
        .recv(&mut buf)
        .with_context(|| format!("GET_CONFIG reply from {ifname}"))?;
    Ok(parse_config(
        std::str::from_utf8(&buf[..n]).context("GET_CONFIG reply is not UTF-8")?,
    ))
}

/// BSSID hostapd runs on `ifname`.
pub fn bssid(ifname: &str) -> Result<[u8; 6]> {
    let cfg = get_config(ifname)?;
    let text = cfg
        .get("bssid")
        .with_context(|| format!("hostapd on {ifname} reports no bssid"))?;
    crate::config::mac(text).with_context(|| format!("bssid of {ifname}"))
}

/// BSSIDs of every hostapd-managed wifi interface on this host. Used to
/// fill a peer's empty `bssids` list: in this deployment every local BSS is
/// a legitimate RRB source.
pub fn bssids() -> Result<Vec<[u8; 6]>> {
    let mut out = vec![];
    for entry in std::fs::read_dir(SOCKET_DIR).with_context(|| format!("read {SOCKET_DIR}"))? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF-8 name in {SOCKET_DIR}"))?;
        if !name.starts_with(SOCKET_PREFIX) {
            continue;
        }
        out.push(bssid(&name)?);
    }
    ensure!(
        !out.is_empty(),
        "no hostapd sockets under {SOCKET_DIR}/{SOCKET_PREFIX}*"
    );
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// key=value lines; blank lines and anything without '=' are ignored.
fn parse_config(text: &str) -> Config {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_config_reply() {
        let cfg = parse_config("bssid=22:0b:8b:ea:60:c9\nssid=Home\nkey_mgmt=FT-PSK\n\njunkline\n");
        assert_eq!(cfg["bssid"], "22:0b:8b:ea:60:c9");
        assert!(!cfg.contains_key("junkline"));
        assert_eq!(cfg.len(), 3);
    }
}
