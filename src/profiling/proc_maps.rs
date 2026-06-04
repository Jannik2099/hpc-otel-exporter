//! Parsing of `/proc/<pid>/maps` and translation of runtime addresses into the
//! `.eh_frame` (module virtual) address space the unwind tables are keyed by.
//!
//! Only file-backed *executable* mappings matter to the unwinder: a sampled PC
//! always lies in executable code, and we unwind by looking up that file's
//! table. For each such mapping we record where it lives in memory, a stable id
//! for the backing file (so identical files share one table), and the
//! `load_offset` that maps a runtime PC back to its module virtual address.

use std::hash::{Hash, Hasher};

use super::unwind::LoadSegment;

/// One file-backed executable mapping line from `/proc/<pid>/maps`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawMapping {
    pub begin: u64,
    pub end: u64,
    /// File offset of the first mapped byte (the `offset` column).
    pub file_offset: u64,
    /// Encoded device (major:minor) of the backing filesystem.
    pub dev: u64,
    pub inode: u64,
    pub path: String,
}

/// Parse the executable, file-backed mappings out of a `/proc/<pid>/maps` body.
/// Non-executable, anonymous, and pseudo (`[heap]`, `[vdso]`, …) mappings are
/// skipped — we can neither find nor read unwind info for them.
pub fn parse_maps(content: &str) -> Vec<RawMapping> {
    content.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<RawMapping> {
    // Format: `begin-end perms offset dev inode pathname`
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let offset = fields.next()?;
    let dev = fields.next()?;
    let inode = fields.next()?;
    // The pathname is the remainder; it may itself contain spaces.
    let path = line[line.len() - line.trim_start().len()..]
        .splitn(6, char::is_whitespace)
        .nth(5)
        .map(str::trim)
        .unwrap_or("");

    // Executable code only (perms looks like "r-xp").
    if perms.as_bytes().get(2) != Some(&b'x') {
        return None;
    }
    // Must be a real, readable file: a non-zero inode and a concrete path
    // (skip anonymous maps and kernel pseudo-files like [vdso]/[stack]).
    let inode: u64 = inode.parse().ok()?;
    if inode == 0 || path.is_empty() || path.starts_with('[') {
        return None;
    }

    let (begin, end) = range.split_once('-')?;
    let (major, minor) = dev.split_once(':')?;

    Some(RawMapping {
        begin: u64::from_str_radix(begin, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        file_offset: u64::from_str_radix(offset, 16).ok()?,
        dev: encode_dev(
            u32::from_str_radix(major, 16).ok()?,
            u32::from_str_radix(minor, 16).ok()?,
        ),
        inode,
        path: path.to_owned(),
    })
}

fn encode_dev(major: u32, minor: u32) -> u64 {
    ((major as u64) << 32) | minor as u64
}

/// A stable identifier for a backing file: distinct files get distinct ids, and
/// the same file mapped by many processes gets the same id (so its unwind table
/// is parsed and loaded once). Keyed on `(device, inode)`.
pub fn exec_id(dev: u64, inode: u64) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    dev.hash(&mut h);
    inode.hash(&mut h);
    h.finish()
}

// See ### Mapping a runtime PC to a module VA in profiler.md
pub fn segment_for_mapping(
    segments: &[LoadSegment],
    file_offset: u64,
    len: u64,
) -> Option<&LoadSegment> {
    segments
        .iter()
        .find(|s| file_offset < s.p_offset + s.p_filesz && file_offset + len > s.p_offset)
}

/// The offset to subtract from a runtime PC to get its module virtual address
/// (`mva = pc - load_offset`), for a mapping backed by `segment`.
///
/// Derivation: a runtime byte at `pc` is at file offset `file_offset + (pc -
/// begin)`, which in segment `S` has module VA `p_vaddr + (file_off -
/// p_offset)`. Solving `mva = pc - load_offset` gives the expression below.
/// Computed with wrapping arithmetic since the BPF side mirrors it on addresses.
///
/// `file_offset` is the (possibly page-rounded-down) value from `/proc/maps`; it
/// may sit a little below `segment.p_offset` (see [`segment_for_mapping`]). That is
/// fine: the result is still correct for every real code PC, whose own file offset
/// is `>= p_offset`. Only the first sub-page of rounding slack would map to a
/// negative in-segment offset, and no executed instruction lives there.
pub fn compute_load_offset(begin: u64, file_offset: u64, segment: &LoadSegment) -> u64 {
    begin
        .wrapping_sub(file_offset)
        .wrapping_sub(segment.p_vaddr.wrapping_sub(segment.p_offset))
}

/// The `[begin, end)` virtual-address range of the `/proc/<pid>/maps` line whose
/// mapping contains `addr`, if any.
///
/// Unlike [`parse_maps`], this considers *every* mapping — anonymous, `memfd`,
/// non-ELF (e.g. a Wine PE/DLL) — not just executable ELF files. It exists to
/// negatively cache a whole un-symbolizable region: such regions (notably JIT
/// areas) churn through fresh addresses, so caching a single failing address is
/// useless, but the enclosing mapping is stable.
pub fn range_containing(content: &str, addr: u64) -> Option<(u64, u64)> {
    content.lines().find_map(|line| {
        let range = line.split_whitespace().next()?;
        let (begin, end) = range.split_once('-')?;
        let begin = u64::from_str_radix(begin, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        (addr >= begin && addr < end).then_some((begin, end))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_containing_finds_enclosing_mapping() {
        // A churning JIT address must resolve to its (stable) memfd region even
        // though that mapping is not an executable ELF parse_maps would return.
        let maps = "\
55a3b2c00000-55a3b2c01000 r-xp 00001000 fd:01 1311406 /usr/bin/foo
7f3c00000000-7f3c00400000 r-xp 00000000 00:00 1234 /memfd:wine-jit (deleted)
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]";
        assert_eq!(
            range_containing(maps, 0x7f3c00123456),
            Some((0x7f3c00000000, 0x7f3c00400000))
        );
        // An address in the ELF mapping is also found...
        assert_eq!(
            range_containing(maps, 0x55a3b2c00500),
            Some((0x55a3b2c00000, 0x55a3b2c01000))
        );
        // ...while an address in no mapping is not.
        assert_eq!(range_containing(maps, 0x10), None);
    }

    #[test]
    fn parses_executable_file_mappings_only() {
        let maps = "\
55a3b2c00000-55a3b2c01000 r-xp 00001000 fd:01 1311406 /usr/bin/foo
55a3b2c01000-55a3b2c02000 rw-p 00002000 fd:01 1311406 /usr/bin/foo
7f1200000000-7f1200021000 r-xp 00000000 fd:01 99 /usr/lib/libc.so.6
7f12aaaaa000-7f12aaaab000 rw-p 00000000 00:00 0 \n\
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
7ffd000ff000-7ffd00100000 r-xp 00000000 00:00 0 [vdso]";
        let parsed = parse_maps(maps);
        let paths: Vec<&str> = parsed.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(paths, vec!["/usr/bin/foo", "/usr/lib/libc.so.6"]);

        let foo = &parsed[0];
        assert_eq!(foo.begin, 0x55a3b2c00000);
        assert_eq!(foo.end, 0x55a3b2c01000);
        assert_eq!(foo.file_offset, 0x1000);
        assert_eq!(foo.inode, 1311406);
        assert_eq!(foo.dev, encode_dev(0xfd, 0x01));
    }

    #[test]
    fn handles_paths_with_spaces() {
        let line = "55a3b2c00000-55a3b2c01000 r-xp 00000000 fd:01 7 /opt/my app/bin";
        let m = parse_line(line).expect("executable mapping");
        assert_eq!(m.path, "/opt/my app/bin");
    }

    #[test]
    fn load_offset_pie_and_non_pie() {
        // PIE: executable segment p_vaddr 0x1000 at file offset 0x1000, loaded
        // at base 0x55_5555_5000. A PC at `begin` must map to p_vaddr 0x1000.
        let seg = LoadSegment {
            p_offset: 0x1000,
            p_vaddr: 0x1000,
            p_filesz: 0x4000,
        };
        let begin = 0x5555_5555_5000;
        let lo = compute_load_offset(begin, 0x1000, &seg);
        assert_eq!(begin.wrapping_sub(lo), 0x1000);
        // A PC 0x200 into the mapping maps 0x200 into the module.
        assert_eq!((begin + 0x200).wrapping_sub(lo), 0x1200);

        // Non-PIE: vaddr == runtime address, so the module VA is the PC itself.
        let seg = LoadSegment {
            p_offset: 0x1000,
            p_vaddr: 0x401000,
            p_filesz: 0x4000,
        };
        let lo = compute_load_offset(0x401000, 0x1000, &seg);
        assert_eq!(lo, 0);
        assert_eq!(0x401234u64.wrapping_sub(lo), 0x401234);
    }

    #[test]
    fn exec_id_is_stable_and_distinct() {
        let a = exec_id(encode_dev(0xfd, 1), 100);
        assert_eq!(a, exec_id(encode_dev(0xfd, 1), 100));
        assert_ne!(a, exec_id(encode_dev(0xfd, 1), 101));
        assert_ne!(a, exec_id(encode_dev(0xfd, 2), 100));
    }

    #[test]
    fn segment_lookup_picks_overlapping_range() {
        let segs = [
            LoadSegment {
                p_offset: 0x0,
                p_vaddr: 0x0,
                p_filesz: 0x1000,
            },
            LoadSegment {
                p_offset: 0x2000,
                p_vaddr: 0x2000,
                p_filesz: 0x1000,
            },
        ];
        // A mapping fully inside a segment resolves to it.
        assert_eq!(
            segment_for_mapping(&segs, 0x2000, 0x1000).unwrap().p_offset,
            0x2000
        );
        // A mapping in the gap between segments resolves to nothing.
        assert!(segment_for_mapping(&segs, 0x1000, 0x1000).is_none());
    }

    #[test]
    fn segment_lookup_tolerates_page_rounded_offset() {
        // The crux: the kernel rounds a non-page-aligned PT_LOAD's file offset
        // *down* to a page, so the maps `file_offset` sits below `p_offset`. A
        // containment test would miss the segment; the overlap test must not.
        let exec = LoadSegment {
            p_offset: 0x326a00, // not page-aligned (real binary value)
            p_vaddr: 0x327a00,
            p_filesz: 0x98e450,
        };
        let segs = [exec];
        let mapping_file_offset = 0x326000; // == p_offset rounded down to a page
        let mapping_len = 0x98f000;
        let seg = segment_for_mapping(&segs, mapping_file_offset, mapping_len)
            .expect("the page-rounded mapping must still resolve to the exec segment");
        assert_eq!(seg.p_offset, 0x326a00);

        // ...and the load offset it yields maps the first real code byte (at
        // p_offset, i.e. begin + (p_offset - file_offset)) back to p_vaddr.
        let begin = 0x5555_5555_5000;
        let lo = compute_load_offset(begin, mapping_file_offset, seg);
        let first_code_pc = begin + (exec.p_offset - mapping_file_offset);
        assert_eq!(first_code_pc.wrapping_sub(lo), exec.p_vaddr);
    }

    #[test]
    fn every_executable_self_mapping_resolves_to_a_segment() {
        // End-to-end regression against real maps: a non-page-aligned executable
        // PT_LOAD makes the kernel report a page-rounded file_offset below
        // p_offset.
        let exe = std::fs::read_link("/proc/self/exe").expect("readlink exe");
        let info = crate::profiling::unwind::parse_executable(&exe).expect("parse exe");
        let exe_str = exe.to_string_lossy();
        let maps = std::fs::read_to_string("/proc/self/maps").expect("read maps");

        let mut checked = 0;
        for m in parse_maps(&maps) {
            if m.path != exe_str {
                continue;
            }
            assert!(
                segment_for_mapping(&info.exec_segments, m.file_offset, m.end - m.begin).is_some(),
                "executable self-mapping {:#x}-{:#x} (file offset {:#x}) resolved to no \
                 executable segment",
                m.begin,
                m.end,
                m.file_offset,
            );
            checked += 1;
        }
        assert!(checked > 0, "expected at least one executable self-mapping");
    }

    #[test]
    fn parses_real_self_maps() {
        let content = std::fs::read_to_string("/proc/self/maps").expect("read maps");
        let parsed = parse_maps(&content);
        assert!(
            !parsed.is_empty(),
            "the test process must have executable file mappings"
        );
        assert!(parsed.iter().all(|m| m.inode != 0 && !m.path.is_empty()));
    }
}
