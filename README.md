# re-rrb-rs

RRB packet relay from the switch-facing ports to hostapd on UDR 5G Max.

A first-principles rewrite of the `rrb-relay` experiment (UniFi 802.11r Fast
Roaming "RRB" relay), with every non-obvious constant documented at the point
of use. This architecture deliberately uses **no eBPF at all**: only passive
packet capture plus one self-cleaning TC `mirred` rule on a TAP device the
daemon owns.

## What it does

The switch delivers RRB frames (EtherType `0x88B7`, protocol selector OUI
`00:13:74` + `00 01`) to the switch-facing ports (`eth1`, `eth2`, ...), but
hostapd listens on the bridge (`br0`), and nothing forwards L2 frames between
the two. The pipeline:

1. **Capture** — an AF_PACKET socket per source port with a classic BPF
   socket filter (`0x8100`+`0x88B7`, or bare `0x88B7`). Purely passive:
   the original frame keeps its path exactly as if we were not there, and
   non-RRB traffic never wakes userspace. VLAN-offloaded tags are recovered
   via `PACKET_AUXDATA`; frames this host itself transmitted
   (`PACKET_OUTGOING`) are skipped so hostapd's own RRB cannot loop back.
2. **Validate + fix (userspace)** — the `proto` parser checks geometry, VLAN
   scope, MACs, RRB header, TLV stream (duplicates rejected), and broadcast
   restrictions (only PULL/SEQ_REQ, must name a configured local R0KH-ID).
   Matching frames get the management VLAN tag popped.
3. **Inject** — the untagged frame is written to a non-persistent relay TAP
   (`rrb0`) created with [tun-rs](https://github.com/tun-rs/tun-rs).
4. **Forward (kernel)** — one TC rule on the TAP:
   `filter ... protocol 0x88b7 u32 matchall action mirred ingress redirect
   dev br0`. The `protocol` match is the kernel-side EtherType gate;
   `mirred ingress redirect` puts the frame on br0's RX path as if received
   there, which is what hostapd needs.

**Teardown is automatic**: the TAP is non-persistent, so when the daemon
exits — cleanly or via SIGKILL — the kernel destroys the device and its TC
rules with it. Nothing ever touches the source ports.

The daemon is fully async (tokio, current-thread): one capture task per
source port, one inject task owning the TAP, a bounded channel in between,
and signal-driven shutdown. Errors use anyhow; logging uses tracing
(stderr, compact, `RUST_LOG`-controlled — `RUST_LOG=rerrb=debug` shows every
matched frame, `rerrb=trace` adds rejections).

## Layout

Single crate, binary `rerrb`:

```text
src/proto/     RRB parser (Filter + classify) and the Counter vocabulary;
               allocation-free, bounded loops, unit-tested on any host
src/config.rs  YAML config (serde): sources / aps / peers / target / limits,
               Filter assembly (fail-closed)
src/hostapd.rs hostapd control-socket client (GET_CONFIG): per-interface
               R0KH-ID, local BSSIDs (Linux)
src/packet.rs  AF_PACKET socket, cBPF filter, PACKET_AUXDATA (Linux)
src/tap.rs     tun-rs TAP + tc mirred attach/destroy/stats (Linux)
src/relay.rs   pure logic: untag, kind counters, rate limiter
src/app.rs     async orchestration: capture/inject tasks, shutdown (Linux)
src/main.rs    clap CLI: run / destroy / stats
config/example.yaml
```

## Usage (on the UDR, as root)

```bash
# forward mode: relay matching RRB into br0
rerrb run --config config/example.yaml

rerrb stats    --tap rrb0   # kernel-side mirred action counters (tc -s)
rerrb destroy  --tap rrb0   # remove leftovers after an unclean death
```

The config lists `sources` (ports RRB arrives on), `aps` (local AP
interfaces; `r0kh_id` defaults to the BSSID in hex without colons — on UniFi
the R0KH-ID is the BSSID), `peers` (allowed senders; each lists the BSSIDs it
may claim — omit `peers` to accept any sender, omit a peer's `bssids` to fill
in every BSSID the local hostapd manages, queried from the
`/run/hostapd/wifi*` control sockets), and `target` (default `br0`). Set
`mode: observe` to validate and count only — the TAP is never created.

Prerequisites: root (or CAP_NET_ADMIN), the `tun` module loaded, `tc`/`ip`
from iproute2. No BPF filesystem, no custom kernel features.

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
