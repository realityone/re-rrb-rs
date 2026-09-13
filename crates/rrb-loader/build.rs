fn main() {
    // Two-stage build: this crate's build script compiles the rrb-ebpf crate
    // with a pinned nightly into a bpfel-unknown-none ELF, which lib.rs then
    // embeds into the host binary. Requires the toolchain, its rust-src
    // component, and bpf-linker on PATH:
    //   rustup toolchain install nightly-2026-04-01 --component rust-src
    //   cargo +nightly-2026-04-01 install bpf-linker --version 0.10.3 --locked
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "rrb-ebpf",
            root_dir: "crates/rrb-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::Custom("nightly-2026-04-01"),
    )
    .expect("build Rust eBPF action (nightly, rust-src and bpf-linker required)");
    println!("cargo:rerun-if-changed=../rrb-common/src");
}
