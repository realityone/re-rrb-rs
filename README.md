# re-rrb-rs

**Fix 802.11r fast roaming on the UniFi Dream Router (UDR) 5G Max** by
relaying RRB frames from the switch-facing ports to hostapd on the bridge.

## The problem

When a client roams between the UDR and another UniFi AP with 802.11r
enabled, the APs coordinate over the wired network ("FT over the
distribution system"): the old AP's R0KH and the new AP's R1KH exchange
**RRB frames** — raw Ethernet, EtherType `0x88B7` — to hand over the
client's PMK so the roam completes without a full reauthentication.

On the UDR this exchange is broken at the last hop:

- RRB frames from the other APs **do arrive** on the UDR's switch-facing
  ports (`eth0`–`eth3`, behind the `switch0` fabric), tagged with the
  management VLAN — you can watch them with tcpdump on those ports.
- But the UDR's hostapd listens on the **bridge** (`br0`, where all the
  `wifiXapY` AP interfaces are enslaved) — and the frames never appear
  there.

With the over-DS path dead, every roam into or out of the UDR falls back
to a full authentication: hundreds of milliseconds of interruption instead
of a seamless handoff — audible in calls, visible in streams.

## The fix

`rerrb` is a small userspace daemon that closes exactly that gap, and
nothing else:

```text
eth1/eth2 (passive AF_PACKET capture, like tcpdump — the wire is untouched)
   │  RRB candidates only (kernel cBPF filter: EtherType 0x88B7)
   ▼
userspace validation: really RRB? for this UDR? from a known peer?
   │  strip the management VLAN tag
   ▼
private TAP device `rrb0` (created and owned by rerrb)
   │  one tc mirred rule: protocol 0x88b7 → redirect ingress to br0
   ▼
br0 RX → hostapd receives the frame exactly as if the NIC had delivered it
```

Design properties:

- **No eBPF, no kernel changes, no switch/VLAN/hostapd reconfiguration.**
  The capture side never alters the original frame's path; the forward
  side is a single `tc mirred` rule on a device only rerrb owns.
- **Self-cleaning.** The TAP is non-persistent: when rerrb exits — cleanly
  or via SIGKILL — the kernel destroys the device and its tc rules. There
  is no persistent state to leak.
- **Fail-closed validation.** Frames must match the management VLAN, the
  bridge MAC (or restricted broadcast), configured peer APs, and local
  BSS/R0KH identities; TLV structure is fully validated. Cryptography is
  *not* reimplemented — the authenticator trailer is length-checked and
  hostapd remains the cryptographic authority.
- **Bounded blast radius.** A shared per-second relay budget caps how much
  can be injected, and matched/rejected frames are counted and logged.

## Install (UDR)

The [release](https://github.com/realityone/re-rrb-rs/releases) ships an
`rerrb_arm64.deb`:

```bash
dpkg -i rerrb_arm64.deb        # installs /usr/bin/rerrb, the systemd unit,
                               # and /etc/rerrb/config.yaml
vi /etc/rerrb/config.yaml      # set sources/aps/peers for your topology
systemctl restart rerrb
journalctl -u rerrb -f         # RUST_LOG=rerrb=debug shows every roam
```

The unit is enabled and started on install, and ordered after
`hostapd-global.service` because rerrb reads BSSIDs from hostapd's control
sockets when a peer leaves `bssids` empty — and since UniFi's hostapd
backgrounds its per-BSS setup, startup retries the socket discovery for
~30s. The config file is a dpkg
conffile — your edits survive upgrades.

## Configuration

See [config/example.yaml](config/example.yaml). The essentials:

```yaml
sources: [eth1, eth2]      # ports where RRB frames arrive
aps:                       # local AP interfaces this relay serves;
  - interface: wifi1ap4    #   r0kh_id defaults to the BSSID hex without
                           #   colons (UniFi: R0KH-ID == BSSID)
peers:                     # other APs allowed to send us RRB;
  - mac: "1c:0b:8b:ea:60:c9"  #   empty `bssids` = all BSSIDs hostapd manages
    bssids: ["1c:0b:8b:ea:60:c9"]
target: br0                # bridge hostapd listens on
mode: forward              # observe = validate/count only, never forwards
```

Useful CLI:

```bash
rerrb run --config /etc/rerrb/config.yaml   # foreground (what systemd runs)
rerrb stats --tap rrb0                      # kernel-side tc counters
rerrb destroy --tap rrb0                    # remove leftovers (never needed
                                            # after a clean or killed exit)
```

## Build and test

```bash
cargo build --release
cargo test           # parser + relay + config unit tests (run on any host)
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

The Linux-only modules (AF_PACKET/TAP/tc) are `cfg(target_os = "linux")`;
cross-check them from macOS with:

```bash
rustup target add aarch64-unknown-linux-gnu
cargo clippy --target aarch64-unknown-linux-gnu --all-targets -- -D warnings
```

Releases: pushing a `v*` tag runs
[.github/workflows/release.yml](.github/workflows/release.yml), which
cross-builds aarch64 and attaches `rerrb_arm64.deb` to a GitHub release.

## Layout

Single crate, binary `rerrb`:

```text
src/proto/     RRB parser (Filter + classify) and the Counter vocabulary;
               allocation-free, bounded loops, unit-tested on any host
src/config.rs  YAML config (serde): sources / aps / peers / target / limits,
               Filter assembly (fail-closed)
src/hostapd.rs hostapd control-socket client (GET_CONFIG): local BSSIDs
src/packet.rs  AF_PACKET socket, cBPF filter, PACKET_AUXDATA (Linux)
src/tap.rs     tun-rs TAP + tc mirred attach/destroy/stats (Linux)
src/relay.rs   pure logic: untag, kind counters, rate limiter
src/app.rs     async orchestration: capture/inject tasks, shutdown (Linux)
src/main.rs    clap CLI: run / destroy / stats
debian/        systemd unit for the deb package
config/example.yaml
```
