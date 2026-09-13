//! YAML configuration of the relay daemon, and the translation into the
//! parser's [`Filter`] identity.
//!
//! Example:
//!
//! ```yaml
//! sources: [eth1, eth2]        # ports RRB frames arrive on (from the switch)
//! aps:                         # local AP interfaces this relay serves
//!   - interface: wifi1ap4
//!     # r0kh_id defaults to the interface's BSSID in hex without colons,
//!     # which is what UniFi's hostapd configures.
//! peers:                       # peer APs allowed to send us RRB
//!   - mac: "1c:0b:8b:ea:60:c9"
//!     bssid: "1c:0b:8b:ea:60:c9"
//! target: br0                  # bridge hostapd listens on
//! ```
use crate::proto::{Filter, Local, MAX_LOCALS, MAX_PEER_BSSIDS, MAX_PEERS, MAX_R0KH, Peer};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::HashSet;

/// Default TC filter priority on the relay TAP: 0xC000, high in the kernel's
/// range, far from anything another tool would auto-assign. The device is
/// ours alone, so this only needs to be stable, not coordinated.
pub const DEFAULT_PREF: u16 = 49152;

fn default_target() -> String {
    "br0".to_string()
}
fn default_vlan() -> u16 {
    1 // UDR management VLAN
}
fn default_mode() -> Mode {
    Mode::Forward
}
fn default_pps() -> u32 {
    20 // a roam generates a handful of RRB frames; 20/s is generous headroom
}
fn default_tap() -> String {
    "rrb0".to_string()
}
fn default_pref() -> u16 {
    DEFAULT_PREF
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Validate and count only; no TAP, no forwarding.
    Observe,
    /// Relay matched frames into the target bridge.
    Forward,
}

/// One local AP interface the relay serves.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApEntry {
    /// AP interface name (e.g. wifi1ap4); its MAC is the local BSSID.
    pub interface: String,
    /// R0KH-ID hostapd uses for this BSS (1..=48 ASCII bytes). Default:
    /// the interface's BSSID in lowercase hex without colons — on UniFi the
    /// R0KH-ID is the BSSID.
    pub r0kh_id: Option<String>,
}

/// One peer AP allowed to source RRB traffic toward us.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    /// MAC address the peer puts in the Ethernet source field.
    pub mac: String,
    /// BSSIDs the peer may claim inside the RRB header (0..=8). Empty =
    /// filled with every BSSID this host's hostapd manages (queried from
    /// /run/hostapd/wifi* control sockets).
    #[serde(default)]
    pub bssids: Vec<String>,
}

/// Rate limit on relayed frames.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Relays allowed per 1-second window.
    #[serde(default = "default_pps")]
    pub packets_per_second: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            packets_per_second: default_pps(),
        }
    }
}

/// Root of the YAML config file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Switch-facing ports RRB frames arrive on, e.g. [eth1, eth2].
    pub sources: Vec<String>,
    /// Local AP interfaces this relay serves (1..=8).
    pub aps: Vec<ApEntry>,
    /// Peer APs allowed to send us RRB frames (0..=8). Empty = wildcard:
    /// any sender is accepted as a peer.
    #[serde(default)]
    pub peers: Vec<PeerEntry>,
    /// Bridge that hostapd listens on; the mirred redirect target.
    #[serde(default = "default_target")]
    pub target: String,
    /// 802.1Q VID RRB frames must be tagged with on the wire.
    #[serde(default = "default_vlan")]
    pub management_vlan: u16,
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(default)]
    pub limits: Limits,
    /// Name of the relay TAP to create (forward mode only).
    #[serde(default = "default_tap")]
    pub tap: String,
    /// TC filter priority on the TAP.
    #[serde(default = "default_pref")]
    pub pref: u16,
}

impl Settings {
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
        let settings: Settings =
            serde_yaml::from_str(&text).with_context(|| format!("parse config {path}"))?;
        settings.validate()?;
        Ok(settings)
    }

    /// Structural validation that does not need the OS. Interface existence
    /// is checked lazily: sources at socket open, APs/target in `filter()`.
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.sources.is_empty(), "configure at least one source");
        ensure!(
            (1..=MAX_LOCALS).contains(&self.aps.len()),
            "configure 1..{MAX_LOCALS} AP interfaces"
        );
        ensure!(
            self.peers.len() <= MAX_PEERS,
            "configure at most {MAX_PEERS} peers"
        );
        let mut names = HashSet::new();
        for name in self
            .sources
            .iter()
            .chain(self.aps.iter().map(|a| &a.interface))
            .chain([&self.target, &self.tap])
        {
            ensure!(
                !name.is_empty()
                    && name.len() < 16 // IFNAMSIZ
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
                "invalid interface name {name:?}"
            );
            ensure!(names.insert(name), "interface {name:?} listed twice");
        }
        ensure!(self.management_vlan > 0, "management_vlan must be 1..4094");
        ensure!(
            self.limits.packets_per_second > 0,
            "packets_per_second must be >= 1"
        );
        Ok(())
    }

    /// Assemble the userspace filter identity, fail-closed on bad input.
    /// Reads MACs from sysfs; hostapd control sockets are queried only when
    /// a peer leaves `bssids` empty.
    pub fn filter(&self) -> Result<Filter> {
        let mut f = Filter {
            target_mac: sysfs_mac(&self.target)?,
            management_vlan: self.management_vlan,
            peer_count: self.peers.len() as u8,
            local_count: self.aps.len() as u8,
            ..Filter::default()
        };
        for (i, ap) in self.aps.iter().enumerate() {
            let bssid =
                sysfs_mac(&ap.interface).with_context(|| format!("local AP {}", ap.interface))?;
            let r0kh_id = match &ap.r0kh_id {
                Some(id) => id.clone(),
                // UniFi convention: the R0KH-ID is the BSSID in lowercase
                // hex without colons (e.g. 22:0b:8b:ea:60:c9 ->
                // "220b8bea60c9").
                None => bssid.iter().map(|b| format!("{b:02x}")).collect(),
            };
            ensure!(
                !r0kh_id.is_empty() && r0kh_id.len() <= MAX_R0KH && r0kh_id.is_ascii(),
                "r0kh_id of {} must be 1..{MAX_R0KH} ASCII bytes",
                ap.interface
            );
            // A broadcast BSSID would admit every broadcast frame as "for us".
            ensure!(bssid != [255; 6], "BSSID of {} is broadcast", ap.interface);
            ensure!(
                !f.locals[..i].iter().any(|l| l.bssid == bssid),
                "duplicate BSSID {bssid:02x?} ({})",
                ap.interface
            );
            let mut local = Local {
                bssid,
                r0kh_len: r0kh_id.len() as u8,
                ..Local::default()
            };
            local.r0kh[..r0kh_id.len()].copy_from_slice(r0kh_id.as_bytes());
            f.locals[i] = local;
        }
        // Peers with an empty `bssids` list accept every BSSID this host's
        // hostapd manages; the set is queried once, lazily.
        let mut all_bssids: Option<Vec<[u8; 6]>> = None;
        for (i, p) in self.peers.iter().enumerate() {
            let m = mac(&p.mac)?;
            ensure!(m != [255; 6], "peer MAC must not be broadcast");
            ensure!(
                !f.peers[..i].iter().any(|q| q.mac == m),
                "duplicate peer MAC {m:02x?}"
            );
            let bssids: Vec<[u8; 6]> = if p.bssids.is_empty() {
                match &all_bssids {
                    Some(v) => v.clone(),
                    None => {
                        let v =
                            bssids_with_retry().context("discover local BSSIDs from hostapd")?;
                        all_bssids = Some(v.clone());
                        v
                    }
                }
            } else {
                p.bssids
                    .iter()
                    .map(|b| mac(b))
                    .collect::<Result<_>>()
                    .with_context(|| format!("peer {m:02x?}"))?
            };
            ensure!(
                !bssids.is_empty(),
                "peer {m:02x?}: no BSSIDs (hostapd reported none)"
            );
            ensure!(
                bssids.len() <= MAX_PEER_BSSIDS,
                "peer {m:02x?}: at most {MAX_PEER_BSSIDS} BSSIDs"
            );
            let mut peer = Peer {
                mac: m,
                bssid_count: bssids.len() as u8,
                ..Peer::default()
            };
            for (j, b) in bssids.iter().enumerate() {
                ensure!(*b != [255; 6], "peer BSSID must not be broadcast");
                ensure!(
                    !bssids[..j].contains(b),
                    "duplicate BSSID {b:02x?} on peer {m:02x?}"
                );
                peer.bssids[j] = *b;
            }
            f.peers[i] = peer;
        }
        Ok(f)
    }
}

/// MAC address of an interface, read from sysfs.
fn sysfs_mac(name: &str) -> Result<[u8; 6]> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .with_context(|| format!("read MAC of {name}"))?;
    mac(text.trim())
}

/// hostapd BSSIDs with startup tolerance: on UniFi OS hostapd-global
/// backgrounds its per-BSS setup (nohup in ExecStartPost), so the
/// /run/hostapd/wifi* control sockets can appear tens of seconds after the
/// unit is "started". Poll for up to ~30s before giving up; 1s between
/// attempts keeps a permanently-broken setup from hanging boot forever.
fn bssids_with_retry() -> Result<Vec<[u8; 6]>> {
    let mut last_err = None;
    for _ in 0..30 {
        match crate::hostapd::bssids() {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(last_err.expect("loop runs at least once"))
}

/// "xx:xx:xx:xx:xx:xx" (hex, any case) into bytes.
pub fn mac(s: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    ensure!(
        parts.len() == 6,
        "invalid MAC {s:?}: want 6 colon-separated octets"
    );
    for (i, p) in parts.iter().enumerate() {
        ensure!(
            p.len() == 2,
            "invalid MAC {s:?}: octet {p:?} must be 2 hex digits"
        );
        out[i] = u8::from_str_radix(p, 16).with_context(|| format!("invalid MAC {s:?}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parsing() {
        assert_eq!(
            mac("22:0b:8b:ea:60:c9").unwrap(),
            [0x22, 0x0b, 0x8b, 0xea, 0x60, 0xc9]
        );
        assert!(mac("22:0b:8b:ea:60").is_err());
        assert!(mac("22:0b:8b:ea:60:cg").is_err());
        assert!(mac("220b8bea60c9").is_err());
    }

    #[test]
    fn yaml_minimal_and_full() {
        // peers omitted entirely: wildcard, accept all senders.
        let minimal: Settings = serde_yaml::from_str(
            r#"
sources: [eth1]
aps:
  - interface: wifi1ap4
"#,
        )
        .unwrap();
        assert_eq!(minimal.target, "br0");
        assert_eq!(minimal.management_vlan, 1);
        assert_eq!(minimal.mode, Mode::Forward);
        assert_eq!(minimal.limits.packets_per_second, 20);
        assert_eq!(minimal.tap, "rrb0");
        assert_eq!(minimal.pref, DEFAULT_PREF);
        minimal.validate().unwrap();

        let full: Settings = serde_yaml::from_str(
            r#"
sources: [eth1, eth2]
aps:
  - interface: wifi1ap4
    r0kh_id: my-r0kh-id
peers:
  - mac: "1c:0b:8b:ea:60:c9"
    bssids: ["1c:0b:8b:ea:60:c9", "22:0b:8b:ea:60:c9"]
  - mac: "1c:0b:8b:ea:60:c8"
target: br1
management_vlan: 10
mode: observe
limits:
  packets_per_second: 5
tap: rrb1
pref: 1234
"#,
        )
        .unwrap();
        assert_eq!(full.mode, Mode::Observe);
        assert_eq!(full.limits.packets_per_second, 5);
        assert_eq!(full.pref, 1234);
        assert_eq!(full.peers[0].bssids.len(), 2);
        assert!(full.peers[1].bssids.is_empty()); // wildcard peer
        full.validate().unwrap();
    }

    #[test]
    fn yaml_rejects_bad_shape() {
        // Unknown field
        assert!(serde_yaml::from_str::<Settings>("sources: [eth1]\naps: []\nbogus: 1").is_err());
        // Singular `bssid` no longer exists
        assert!(
            serde_yaml::from_str::<Settings>(
                "sources: [eth1]\naps:\n  - interface: wifi1ap4\npeers:\n  - mac: \"1c:0b:8b:ea:60:c9\"\n    bssid: \"1c:0b:8b:ea:60:c9\"\n",
            )
            .is_err()
        );
        // No sources
        let s: Settings =
            serde_yaml::from_str("sources: []\naps:\n  - interface: wifi1ap4\n").unwrap();
        assert!(s.validate().is_err());
        // Same interface twice
        let s: Settings =
            serde_yaml::from_str("sources: [eth1, eth1]\naps:\n  - interface: wifi1ap4\n").unwrap();
        assert!(s.validate().is_err());
    }
}
