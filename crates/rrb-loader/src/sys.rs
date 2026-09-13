//! Raw `bpf()` syscall layer (Linux only).
//!
//! `union bpf_attr` offsets below follow the UAPI from the Linux 5.4
//! headers; newer kernels grew the union but still accept the shorter
//! sizes, so we allocate a fixed 144-byte buffer — the 5.4-era
//! `sizeof(union bpf_attr)` — and pass the command-specific prefix length.
//!
//! Command numbers are the kernel's `enum bpf_cmd`; only the ones used here
//! are named.
use crate::{ELF, MAP_CONTRACT, PROG_TYPE_SCHED_ACT, PROGRAM_NAME, budget_btf};
use anyhow::{Context, Result, bail, ensure};
use aya_obj::Object;
use rrb_common::{ABI, Budget, COUNTER_NAMES, Config};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs, io,
    mem::size_of,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};

// --- enum bpf_cmd ---------------------------------------------------------
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_PROG_LOAD: u32 = 5;
const BPF_OBJ_PIN: u32 = 6;
const BPF_OBJ_GET: u32 = 7;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_BTF_LOAD: u32 = 18;

// --- flags ----------------------------------------------------------------
/// map_update_elem flag: create or overwrite the entry.
const BPF_ANY: u64 = 0;
/// map_lookup_elem flag: perform the lookup under the map's spinlock, so a
/// struct containing bpf_spin_lock is copied out consistently.
const BPF_F_LOCK: u64 = 4;

/// sizeof(union bpf_attr) as of Linux 5.4; zeroed padding keeps every
/// reserved field 0, which older kernels require.
const ATTR_LEN: usize = 144;

/// Scratch buffer for `bpf()`: raw bytes we poke fields into by offset.
struct Attr([u8; ATTR_LEN]);
impl Attr {
    fn new() -> Self {
        Self([0; ATTR_LEN])
    }
    fn u32(&mut self, off: usize, n: u32) {
        self.0[off..off + 4].copy_from_slice(&n.to_ne_bytes());
    }
    fn u64(&mut self, off: usize, n: u64) {
        self.0[off..off + 8].copy_from_slice(&n.to_ne_bytes());
    }
    /// Copy an object name into a 16-byte BPF name field (BPF_OBJ_NAME_LEN).
    fn name(&mut self, off: usize, n: &str) -> Result<()> {
        ensure!(n.len() < 16, "BPF name too long");
        self.0[off..off + n.len()].copy_from_slice(n.as_bytes());
        Ok(())
    }
    fn call(&mut self, cmd: u32, len: usize) -> io::Result<i32> {
        // The kernel only copies `len` bytes; every field beyond the
        // command-specific prefix must be 0.
        let rc = unsafe { libc::syscall(libc::SYS_bpf, cmd, self.0.as_mut_ptr(), len) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as i32)
        }
    }
    fn fd(&mut self, cmd: u32, len: usize) -> io::Result<OwnedFd> {
        let fd = self.call(cmd, len)?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Raise this process's RLIMIT_MEMLOCK. Before Linux 5.11, all BPF
/// allocations are charged against it; 16 MiB comfortably covers three
/// small maps, one program, and verifier scratch. Touches only the loader
/// process — never a global sysctl or service.
pub fn raise_memlock() -> Result<()> {
    const NEEDED: u64 = 16 * 1024 * 1024;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0,
        "get RLIMIT_MEMLOCK failed"
    );
    if limit.rlim_cur < NEEDED {
        limit.rlim_cur = NEEDED;
        limit.rlim_max = limit.rlim_max.max(NEEDED);
        ensure!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } == 0,
            "raise loader RLIMIT_MEMLOCK to 16 MiB: {}",
            io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Fetch `struct bpf_*_info` for a program or map fd. 256 bytes cover both
/// structs with generous headroom for fields added after 5.4.
pub fn info(fd: RawFd) -> Result<Vec<u8>> {
    let mut out = vec![0; 256];
    let mut attr = Attr::new();
    attr.u32(0, fd as u32); // info.bpf_fd
    attr.u32(4, out.len() as u32); // info.info_len
    attr.u64(8, out.as_mut_ptr() as u64); // info.info
    attr.call(BPF_OBJ_GET_INFO_BY_FD, 16)
        .context("BPF_OBJ_GET_INFO_BY_FD")?;
    Ok(out)
}

/// Verify `fd` is a SCHED_ACT program and return its kernel-assigned id.
/// bpf_prog_info layout: type@0, id@4.
pub fn program_id(fd: RawFd) -> Result<u32> {
    let data = info(fd)?;
    ensure!(
        u32_at(&data, 0) == PROG_TYPE_SCHED_ACT,
        "program is not SCHED_ACT"
    );
    Ok(u32_at(&data, 4))
}

/// Pin an object into bpffs. Layout: pathname@0 (ptr), bpf_fd@8.
pub fn pin(fd: RawFd, path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut attr = Attr::new();
    attr.u64(0, path.as_ptr() as u64);
    attr.u32(8, fd as u32);
    attr.call(BPF_OBJ_PIN, 16).context("pin BPF object")?;
    Ok(())
}

/// Open a pinned object. Layout: pathname@0 (ptr).
pub fn get(path: &Path) -> Result<OwnedFd> {
    let cpath = CString::new(path.as_os_str().as_bytes())?;
    let mut attr = Attr::new();
    attr.u64(0, cpath.as_ptr() as u64);
    attr.fd(BPF_OBJ_GET, 16)
        .with_context(|| format!("open pinned {}", path.display()))
}

/// Reject a pinned map whose shape does not match the ABI we were built
/// against. bpf_map_info layout: type@0, id@4, key_size@8, value_size@12,
/// max_entries@16.
fn map_shape(fd: RawFd, kind: u32, value: usize, entries: usize) -> Result<()> {
    let i = info(fd)?;
    ensure!(
        u32_at(&i, 0) == kind
            && u32_at(&i, 8) == 4
            && u32_at(&i, 12) as usize == value
            && u32_at(&i, 16) as usize == entries,
        "pinned map ABI mismatch"
    );
    Ok(())
}

/// Shared layout for lookup/update: map_fd@0, key@8 (ptr), value@16 (ptr),
/// flags@24.
fn lookup(fd: RawFd, key: u32, out: &mut [u8], flags: u64) -> Result<()> {
    let mut attr = Attr::new();
    attr.u32(0, fd as u32);
    attr.u64(8, (&key as *const u32) as u64);
    attr.u64(16, out.as_mut_ptr() as u64);
    attr.u64(24, flags);
    attr.call(BPF_MAP_LOOKUP_ELEM, 32)
        .context("BPF_MAP_LOOKUP_ELEM")?;
    Ok(())
}

pub fn write_config(fd: RawFd, c: &Config) -> Result<()> {
    let (kind, value, entries) = MAP_CONTRACT[0].1;
    map_shape(fd, kind, value as usize, entries as usize)?;
    let key = 0u32;
    let mut attr = Attr::new();
    attr.u32(0, fd as u32);
    attr.u64(8, (&key as *const u32) as u64);
    attr.u64(16, (c as *const Config) as u64);
    attr.u64(24, BPF_ANY);
    attr.call(BPF_MAP_UPDATE_ELEM, 32).context("write CONFIG")?;
    Ok(())
}

pub fn read_config(fd: RawFd) -> Result<Config> {
    let (kind, value, entries) = MAP_CONTRACT[0].1;
    map_shape(fd, kind, value as usize, entries as usize)?;
    let mut bytes = [0u8; size_of::<Config>()];
    lookup(fd, 0, &mut bytes, 0)?;
    // Config contains only integer/byte fields; every bit pattern is valid.
    let c = unsafe { bytes.as_ptr().cast::<Config>().read_unaligned() };
    ensure!(c.abi == ABI, "CONFIG ABI version mismatch");
    Ok(c)
}

/// Sum the per-CPU counter slots into a labelled map. A PERCPU_ARRAY lookup
/// returns `n_possible_cpus * 8` bytes, so the CPU count comes from sysfs.
pub fn counters(fd: RawFd) -> Result<BTreeMap<String, u64>> {
    map_shape(fd, MAP_CONTRACT[1].1, 8, COUNTER_NAMES.len())?;
    let possible = fs::read_to_string("/sys/devices/system/cpu/possible")?;
    let mut cpus = 0usize;
    for range in possible.trim().split(',') {
        // Format is comma-separated "start" or "start-end" ranges, e.g. "0-3".
        let mut parts = range.split('-');
        let start: usize = parts.next().context("empty CPU range")?.parse()?;
        let end: usize = parts.next().map(str::parse).transpose()?.unwrap_or(start);
        ensure!(end >= start && end < 65536, "invalid possible CPU range");
        cpus += end - start + 1;
    }
    let mut bytes = vec![0u8; cpus * 8];
    let mut result = BTreeMap::new();
    for (key, name) in COUNTER_NAMES.iter().enumerate() {
        lookup(fd, key as u32, &mut bytes, 0)?;
        result.insert(
            (*name).to_string(),
            bytes
                .chunks_exact(8)
                .map(|v| u64::from_ne_bytes(v.try_into().unwrap()))
                .sum(),
        );
    }
    Ok(result)
}

/// Read `(used, total)` out of the BUDGET map under its spinlock.
pub fn budget(fd: RawFd) -> Result<(u64, u64)> {
    map_shape(fd, MAP_CONTRACT[2].1, size_of::<Budget>(), 1)?;
    let mut bytes = [0u8; size_of::<Budget>()];
    lookup(fd, 0, &mut bytes, BPF_F_LOCK)?;
    Ok((
        u64::from_ne_bytes(bytes[16..24].try_into().unwrap()), // Budget.used
        u64::from_ne_bytes(bytes[24..32].try_into().unwrap()), // Budget.total
    ))
}

/// Load the hand-built BTF blob for `Budget`. btf_load layout: btf@0 (ptr),
/// btf_log_buf@8 (ptr), btf_size@16, btf_log_size@20, btf_log_level@24.
fn load_btf() -> Result<OwnedFd> {
    let bytes = budget_btf();
    let mut log = vec![0u8; 64 * 1024];
    let mut attr = Attr::new();
    attr.u64(0, bytes.as_ptr() as u64);
    attr.u64(8, log.as_mut_ptr() as u64);
    attr.u32(16, bytes.len() as u32);
    attr.u32(20, log.len() as u32);
    attr.u32(24, 1); // log_level 1: request verifier-style diagnostics
    attr.fd(BPF_BTF_LOAD, 28).with_context(|| {
        format!(
            "load map BTF (spinlock requires BTF support): {}",
            log_text(&log)
        )
    })
}

fn log_text(log: &[u8]) -> String {
    String::from_utf8_lossy(&log[..log.iter().position(|v| *v == 0).unwrap_or(log.len())])
        .into_owned()
}

pub struct Loaded {
    pub maps: BTreeMap<String, OwnedFd>,
    pub programs: BTreeMap<String, OwnedFd>,
}

/// Parse the embedded ELF, create its maps, relocate, and load the program
/// as SCHED_ACT. Every shape is checked against `MAP_CONTRACT`/`PROGRAM_NAME`
/// so the loader refuses to run an ELF it was not built for.
pub fn load() -> Result<Loaded> {
    let mut obj = Object::parse(ELF).context("parse embedded BPF ELF")?;
    let btf = load_btf()?;
    let mut maps = BTreeMap::new();
    for (name, m) in &obj.maps {
        let Some(&(.., expected)) = MAP_CONTRACT.iter().find(|e| e.0 == name) else {
            bail!("unexpected map {name}; loader must explicitly support its ABI");
        };
        ensure!(
            (m.map_type(), m.value_size(), m.max_entries()) == expected
                && m.key_size() == 4
                && m.data().is_empty(),
            "unexpected map layout: {name}"
        );
        // map_create layout: map_type@0, key_size@4, value_size@8,
        // max_entries@12, map_flags@16, map_name@28 (16 bytes).
        let mut a = Attr::new();
        a.u32(0, m.map_type());
        a.u32(4, m.key_size());
        a.u32(8, m.value_size());
        a.u32(12, m.max_entries());
        a.u32(16, m.map_flags());
        a.name(28, name)?;
        if name == "BUDGET" {
            // BTF wiring: btf_fd@48, btf_key_type_id@52, btf_value_type_id@56.
            // Type id 1 (u32) for the key; id 4 (Budget struct) for the value.
            a.u32(48, btf.as_raw_fd() as u32);
            a.u32(52, 1);
            a.u32(56, 4);
        }
        maps.insert(
            name.clone(),
            a.fd(BPF_MAP_CREATE, 64)
                .with_context(|| format!("create map {name}"))?,
        );
    }
    ensure!(maps.len() == MAP_CONTRACT.len(), "missing embedded maps");

    let text_sections = obj.functions.keys().map(|(section, _)| *section).collect();
    let definitions = obj.maps.clone();
    obj.relocate_maps(
        maps.iter()
            .map(|(name, fd)| (name.as_str(), fd.as_raw_fd(), &definitions[name])),
        &text_sections,
    )?;
    obj.relocate_calls(&text_sections)?;

    let mut programs = BTreeMap::new();
    for (name, program) in &obj.programs {
        ensure!(name == PROGRAM_NAME, "unexpected program {name}");
        let function = &obj.functions[&program.function_key()];
        // prog_load layout: prog_type@0, insn_cnt@4, insns@8 (ptr),
        // license@16 (ptr), prog_name@48 (16 bytes). prog_type is set
        // explicitly to SCHED_ACT regardless of the ELF section name.
        let mut a = Attr::new();
        a.u32(0, PROG_TYPE_SCHED_ACT);
        a.u32(4, function.instructions.len() as u32);
        a.u64(8, function.instructions.as_ptr() as u64);
        a.u64(16, program.license.as_ptr() as u64);
        a.name(48, name)?;
        // Linux 5.4 can abort verification with ENOSPC when a verbose trace
        // fills its buffer. First verify normally, without requesting a
        // trace; this never disables or relaxes verifier checks. Retry a
        // failed load with diagnostics (log_level@24=1, log_size@28,
        // log_buf@32), preserving the original errno if the log truncated.
        let fd = match a.fd(BPF_PROG_LOAD, 72) {
            Ok(fd) => fd,
            Err(initial) => {
                let mut log = vec![0u8; 16 * 1024 * 1024];
                a.u32(24, 1);
                a.u32(28, log.len() as u32);
                a.u64(32, log.as_mut_ptr() as u64);
                a.fd(BPF_PROG_LOAD, 72).with_context(|| {
                    format!(
                        "load {name} as SCHED_ACT (initial load without trace: {initial}):\n{}",
                        log_text(&log)
                    )
                })?
            }
        };
        program_id(fd.as_raw_fd())?;
        programs.insert(name.clone(), fd);
    }
    ensure!(programs.len() == 1, "missing embedded redirect program");
    Ok(Loaded { maps, programs })
}
