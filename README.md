# re-rrb-rs

eBPF-based RRB packet relay from switch0 to hostapd on UDR 5G Max.

A first-principles rewrite of the eBPF section of the `rrb-relay`
experiment (UniFi 802.11r Fast Roaming "RRB" relay), with every
non-obvious constant documented at the point of use.

## What it does

The switch delivers RRB frames (EtherType `0x88B7`, protocol selector OUI
`00:13:74` + `00 01`) to the switch-facing ports (`eth1`, `eth2`, ...), but
hostapd listens on the bridge (`br0`). A single eBPF **TC action** program on
each configured port's ingress re-validates each frame from scratch
(geometry, VLAN scope, addresses, RRB header, TLV stream, broadcast
restrictions); matching frames get their inner management VLAN tag popped and
are redirected — the original skb, no clone —
into `br0` RX, where hostapd sees them as normally received. Non-matching
frames keep their original path untouched.

Target kernel: Linux 5.4 (UDR firmware) with `NET_ACT_BPF` but no
`NET_CLS_BPF`, so the program loads as `BPF_PROG_TYPE_SCHED_ACT` (4) and
attaches via `tc ingress → u32 → action bpf`.

## Layout

```text
crates/rrb-common/   no_std shared crate: Config/Budget map ABI (compile-time
                     size-asserted), bounded RRB parser, unit tests
crates/rrb-ebpf/     the kernel-side TC action rrb_redirect
                     (no_std + no_main, bpfel-unknown-none)
crates/rrb-loader/   userspace loader: embeds the ELF, hand-builds the BTF
                     blob for the bpf_spin_lock map, and loads via raw bpf()
                     syscalls (Linux-only syscall layer; ELF/BTF logic is
                     portable and unit-tested)
```

The CLI/lifecycle tooling of the original project (YAML config, `tc`/`ip`
orchestration, rtnetlink dumps) is out of scope here; this repo covers only
the eBPF section.

## Build and test

Requires a pinned nightly with rust-src, and bpf-linker:

```bash
rustup toolchain install nightly-2026-04-01 --component rust-src
cargo +nightly-2026-04-01 install bpf-linker --version 0.10.3 --locked
```

Then:

```bash
cargo build          # rrb-loader's build script compiles the eBPF ELF
cargo test           # parser tests + embedded-ELF relocation/BTF tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

eBPF-side clippy (nightly, BPF target):

```bash
AYA_BPF_TARGET_ARCH=aarch64 cargo +nightly-2026-04-01 clippy \
  -p rrb-ebpf --release --target bpfel-unknown-none \
  -Z build-std=core -- -D warnings
```

Note: `cargo build`/`cargo test` work on macOS too — the syscall layer is
`cfg(target_os = "linux")`-gated, and the portable parts (ELF relocation,
BTF construction, parser) are unit-tested on any host.
