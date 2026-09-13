//! Userspace side of the eBPF machinery: embeds the compiled BPF object,
//! builds the tiny BTF blob that teaches the kernel about our spinlock map,
//! and (on Linux) loads everything through raw `bpf()` syscalls.
//!
//! Why raw syscalls instead of Aya's high-level loader: Aya 0.13 only
//! exposes SchedClassifier (`BPF_PROG_TYPE_SCHED_CLS`, 3), but the UDR
//! kernel (Linux 5.4) is built with `CONFIG_NET_ACT_BPF` and *without*
//! `CONFIG_NET_CLS_BPF`. The program must therefore load as
//! `BPF_PROG_TYPE_SCHED_ACT` (4). No patched Aya, external bpftool, kernel
//! BTF, or runtime compiler is required — just this file.
//!
//! Layout: everything that only manipulates bytes (ELF embedding, BTF
//! construction, relocation checks) is portable and unit-testable; the
//! syscall layer is Linux-only and lives in [`sys`].

use rrb_common::{Budget, COUNTER_NAMES, Config};
use std::mem::size_of;

#[cfg(target_os = "linux")]
pub mod sys;

#[cfg(target_os = "linux")]
pub use sys::{
    Loaded, budget, counters, get, info, load, pin, program_id, raise_memlock, read_config,
    write_config,
};

// Same alignment guarantee as aya::include_bytes_aligned!: plain
// include_bytes! only guarantees byte alignment, and the ELF parser may
// reject (or misparse) an unaligned image.
const ELF_LEN: usize = include_bytes!(concat!(env!("OUT_DIR"), "/rrb-action")).len();
#[repr(align(32))]
struct AlignedElf([u8; ELF_LEN]);
static ELF_DATA: AlignedElf = AlignedElf(*include_bytes!(concat!(env!("OUT_DIR"), "/rrb-action")));

/// The compiled `rrb_redirect` action, embedded so the final binary is
/// self-contained: no external `.o`, no bpftool, no toolchain at runtime.
pub const ELF: &[u8] = &ELF_DATA.0;

/// Map ABI contract the loader enforces against the ELF: name →
/// (map_type, value_size, max_entries). `BPF_MAP_TYPE_ARRAY` is 2 and
/// `BPF_MAP_TYPE_PERCPU_ARRAY` is 6 in the kernel's `enum bpf_map_type`;
/// key size is always 4 (a u32 index) for both.
pub const MAP_CONTRACT: [(&str, u32, u32, u32); 3] = [
    ("CONFIG", 2, size_of::<Config>() as u32, 1),
    ("COUNTERS", 6, 8, COUNTER_NAMES.len() as u32),
    ("BUDGET", 2, size_of::<Budget>() as u32, 1),
];

/// Name of the single program inside the ELF.
pub const PROGRAM_NAME: &str = "rrb_redirect";

/// `BPF_PROG_TYPE_SCHED_ACT` in the kernel's `enum bpf_prog_type`: a tc
/// *action* program, attachable via `tc ... action bpf`, which is the only
/// flavour the UDR kernel supports.
pub const PROG_TYPE_SCHED_ACT: u32 = 4;

// ---------------------------------------------------------------------------
// Minimal self-contained BTF for `Budget`.
//
// The kernel only allows bpf_spin_lock inside maps whose value type is
// described by BTF, with the lock member typed as `struct bpf_spin_lock`.
// Rather than depending on /sys/kernel/btf/vmlinux (which the UDR kernel
// does not provide), we hand-build the exact blob for our own 32-byte
// struct. Format reference: Documentation/bpf/btf.rst.
// ---------------------------------------------------------------------------

/// BTF magic number, stored little-endian on disk (bytes 9f eb).
const BTF_MAGIC: u16 = 0xeb9f;
/// BTF format version; 1 is the only version that exists.
const BTF_VERSION: u8 = 1;
/// Size of the BTF header in bytes (magic..str_len inclusive).
const BTF_HEADER_LEN: u32 = 24;
/// `BTF_KIND_INT`: a plain integer type.
const BTF_KIND_INT: u32 = 1;
/// `BTF_KIND_STRUCT`: a struct with `vlen` members following the type.
const BTF_KIND_STRUCT: u32 = 4;
/// Shift of the kind field inside the `info` word of a btf_type
/// (info = kind << 24 | vlen; the kflag bit 31 stays 0).
const BTF_KIND_SHIFT: u32 = 24;

struct BtfBuilder {
    strings: Vec<u8>,
    types: Vec<u8>,
}

impl BtfBuilder {
    fn new() -> Self {
        // String section must start with a NUL so offset 0 means "no name".
        Self {
            strings: vec![0],
            types: Vec::new(),
        }
    }
    fn name(&mut self, s: &str) -> u32 {
        let off = self.strings.len() as u32;
        self.strings.extend(s.as_bytes());
        self.strings.push(0);
        off
    }
    fn push(&mut self, words: &[u32]) {
        for w in words {
            self.types.extend(w.to_ne_bytes());
        }
    }
    /// BTF_KIND_INT type record: name, size in bytes, bit width.
    /// The trailing word packs (encoding << 24 | offset << 16 | bits); we
    /// only need plain unsigned integers, so encoding and offset stay 0.
    fn int(&mut self, name: u32, size: u32, bits: u32) {
        self.push(&[name, BTF_KIND_INT << BTF_KIND_SHIFT, size, bits]);
    }
    /// Start a BTF_KIND_STRUCT record; member records follow.
    fn struct_head(&mut self, name: u32, members: u32, size: u32) {
        self.push(&[name, (BTF_KIND_STRUCT << BTF_KIND_SHIFT) | members, size]);
    }
    /// One struct member: name, type id, offset *in bits* (BTF members are
    /// bit-addressed; byte offsets would silently corrupt the layout).
    fn member(&mut self, name: u32, type_id: u32, bit_offset: u32) {
        self.push(&[name, type_id, bit_offset]);
    }
    /// Serialize: header, then type section, then string section.
    fn finish(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(BTF_MAGIC.to_le_bytes());
        bytes.push(BTF_VERSION);
        bytes.push(0); // flags: none
        bytes.extend(BTF_HEADER_LEN.to_ne_bytes());
        bytes.extend(0u32.to_ne_bytes()); // type_off: types start right after the header
        bytes.extend((self.types.len() as u32).to_ne_bytes());
        bytes.extend((self.types.len() as u32).to_ne_bytes()); // str_off: strings follow types
        bytes.extend((self.strings.len() as u32).to_ne_bytes());
        bytes.extend(self.types);
        bytes.extend(self.strings);
        bytes
    }
}

/// Build the BTF blob describing `Budget`. Type ids are assigned by order:
/// 1 = u32, 2 = u64, 3 = bpf_spin_lock, 4 = Budget.
pub fn budget_btf() -> Vec<u8> {
    const TYPE_U32: u32 = 1;
    const TYPE_U64: u32 = 2;
    const TYPE_SPIN_LOCK: u32 = 3;
    let mut b = BtfBuilder::new();
    let t_u32 = b.name("u32");
    let t_u64 = b.name("u64");
    let t_spin = b.name("bpf_spin_lock");
    let t_val = b.name("val");
    let t_budget = b.name("Budget");
    let fields = [
        b.name("lock"),
        b.name("reserved"),
        b.name("window"),
        b.name("used"),
        b.name("total"),
    ];
    b.int(t_u32, 4, 32);
    b.int(t_u64, 8, 64);
    b.struct_head(t_spin, 1, 4);
    b.member(t_val, TYPE_U32, 0);
    b.struct_head(t_budget, 5, size_of::<Budget>() as u32);
    // (type id, bit offset) per field; must match `repr(C)` Budget exactly.
    for (i, (ty, offset)) in [
        (TYPE_SPIN_LOCK, 0),
        (TYPE_U32, 32),
        (TYPE_U64, 64),
        (TYPE_U64, 128),
        (TYPE_U64, 192),
    ]
    .into_iter()
    .enumerate()
    {
        b.member(fields[i], ty, offset);
    }
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_elf_relocates_without_kernel_operations() {
        let mut obj = aya_obj::Object::parse(ELF).unwrap();
        let maps = obj.maps.clone();
        let mut names: Vec<_> = maps.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["BUDGET", "CONFIG", "COUNTERS"]);
        for (name, m) in &maps {
            assert_eq!(m.key_size(), 4, "{name}");
            assert!(m.data().is_empty(), "no implicit rodata/global maps");
        }
        let expected: std::collections::BTreeMap<_, _> = MAP_CONTRACT
            .iter()
            .map(|e| (e.0, (e.1, e.2, e.3)))
            .collect();
        for (name, m) in &maps {
            let (ty, value, entries) = expected[name.as_str()];
            assert_eq!(
                (m.map_type(), m.value_size(), m.max_entries()),
                (ty, value, entries),
                "{name}"
            );
        }
        let sections = obj.functions.keys().map(|(section, _)| *section).collect();
        // Fake fds are fine here: relocation only rewrites immediates.
        obj.relocate_maps(
            maps.iter()
                .enumerate()
                .map(|(i, (n, m))| (n.as_str(), (100 + i) as std::os::fd::RawFd, m)),
            &sections,
        )
        .unwrap();
        obj.relocate_calls(&sections).unwrap();
        let mut programs: Vec<_> = obj.programs.keys().map(String::as_str).collect();
        programs.sort_unstable();
        assert_eq!(programs, [PROGRAM_NAME]);
        for (name, p) in &obj.programs {
            let instructions = &obj.functions[&p.function_key()].instructions;
            assert!(
                !instructions.is_empty() && instructions.len() < 100_000,
                "{name}"
            );
            // Guard the Linux 5.4 helper ceiling: opcode 0x85 is
            // BPF_JMP|BPF_CALL with src_reg 0 (plain helper call), and imm
            // is the helper id. Only helpers that already existed in 5.4
            // may appear:
            //   1  map_lookup_elem   5  ktime_get_ns   19 skb_vlan_pop
            //  23  redirect         26  skb_load_bytes  93 spin_lock
            //  94  spin_unlock
            for i in instructions {
                if i.code == 0x85 && i.src_reg() == 0 {
                    assert!(
                        [1, 5, 19, 23, 26, 93, 94].contains(&i.imm),
                        "unexpected helper {} in {name}",
                        i.imm
                    );
                }
                // 0xdb/0xc3 are BPF_STX|BPF_ATOMIC (64/32-bit). imm 0 is a
                // plain fetch-add (fine on 5.4); any other imm is a FETCH or
                // CMPXCHG variant requiring a newer kernel.
                if i.code == 0xdb || i.code == 0xc3 {
                    assert_eq!(i.imm, 0, "post-5.4 atomic instruction");
                }
            }
            eprintln!(
                "{name}: {} relocated BPF instructions (not kernel-verified)",
                instructions.len()
            );
        }
    }

    #[test]
    fn spinlock_btf_and_rust_abi_agree() {
        use std::mem::offset_of;
        assert_eq!(offset_of!(Budget, lock), 0);
        assert_eq!(offset_of!(Budget, reserved), 4);
        assert_eq!(offset_of!(Budget, window), 8);
        assert_eq!(offset_of!(Budget, used), 16);
        assert_eq!(offset_of!(Budget, total), 24);
        // Must be a well-formed BTF blob an independent parser accepts.
        let bytes = budget_btf();
        aya_obj::btf::Btf::parse(&bytes, object::Endianness::Little).unwrap();
    }
}
