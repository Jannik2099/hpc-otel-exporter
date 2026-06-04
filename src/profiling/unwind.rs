//! Userspace generation of `.eh_frame` DWARF unwind tables for the in-kernel
//! native stack unwinder.
//!
//! We mirror the binary's own `.eh_frame_hdr`: the linker already builds a
//! sorted, one-entry-per-function search table mapping a PC to its FDE. We walk
//! that table (so the output is sorted without any sorting of our own) and, for
//! each FDE, evaluate its CFI program into [`UnwindRow`]s — one row per address
//! range where the unwind rule set is constant. All functions' rows are
//! concatenated into a single flat, PC-sorted table per executable; the BPF
//! program binary-searches it directly by program counter and applies the rule
//! to step to the caller's frame without frame pointers.
//!
//! Binaries that have `.eh_frame` but no `.eh_frame_hdr` are not unwound (they
//! fall back to a single frame); we do not rebuild the search table ourselves.
//!
//! Only the rules expressible in our compact 16-byte row are emitted (CFA =
//! `rsp`/`rbp` + offset, return address at `*(CFA - 8)`, caller `rbp` saved at a
//! CFA-relative offset or left unchanged). Anything else — DWARF expressions,
//! `.plt` trampolines, frames larger than an `i16` CFA offset, signal frames —
//! becomes a "stopper" row that ends the walk, yielding a partial stack rather
//! than a wrong one. PCs in the gaps between functions (which have no unwind
//! info) are bounded by an end-of-function stopper row inserted wherever a gap
//! follows a function, so the walk stops cleanly rather than inheriting a rule.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use gimli::{
    BaseAddresses, CfaRule, EhFrame, EhFrameHdr, ReaderOffset, Register, RegisterRule,
    RunTimeEndian, UnwindContext, UnwindSection,
};
use log::debug;
use memmap2::Mmap;
use object::{Object, ObjectSection, ObjectSegment, SegmentFlags};

use crate::bindings::{CfaType, MAX_ROWS_PER_EXEC, RbpRule, UnwindRow};

/// DWARF register numbers, x86_64 System V ABI.
const DW_REG_RBP: u16 = 6;
const DW_REG_RSP: u16 = 7;
/// On x86_64 the return address is always read at `CFA - 8`. FDEs specifying any
/// other rule for the return-address register become stopper rows.
const ADDR_SIZE: i64 = 8;
/// ELF program-header `PF_X` (segment is executable).
const PF_X: u32 = 0x1;

/// One executable `PT_LOAD` segment of an ELF, used to translate a runtime PC
/// into the `.eh_frame` (module virtual) address space.
#[derive(Clone, Copy, Debug)]
pub struct LoadSegment {
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
}

/// Everything the loader needs from one backing executable file: its flat unwind
/// table (rows the kernel binary-searches directly), plus the executable segments
/// used to compute per-mapping load offsets.
pub struct ExecutableUnwindInfo {
    /// Number of FDEs (functions) that contributed unwind rows. The kernel no
    /// longer keeps a separate FDE index — rows are searched directly — so this
    /// is informational only, surfaced as the per-cgroup `unwind.fdes` metric.
    pub fde_count: u32,
    pub rows: Vec<UnwindRow>,
    pub exec_segments: Vec<LoadSegment>,
}

/// Parse an ELF once, extracting its flat unwind table and executable segments.
/// The file is mmapped only for the duration of the parse; the returned data is
/// fully owned.
pub fn parse_executable(path: &Path) -> Result<ExecutableUnwindInfo> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    // Safety: we only read the mapping, and it is confined to this function.
    let mmap =
        unsafe { Mmap::map(&file) }.with_context(|| format!("mmapping {}", path.display()))?;
    let obj =
        object::File::parse(&*mmap).with_context(|| format!("parsing ELF {}", path.display()))?;
    let (fde_count, rows) = build_from_object(&obj)?;
    Ok(ExecutableUnwindInfo {
        fde_count,
        rows,
        exec_segments: executable_segments(&obj),
    })
}

/// The executable `PT_LOAD` segments of an ELF, in program-header order.
fn executable_segments(obj: &object::File) -> Vec<LoadSegment> {
    obj.segments()
        .filter(|seg| matches!(seg.flags(), SegmentFlags::Elf { p_flags } if p_flags & PF_X != 0))
        .map(|seg| {
            let (p_offset, p_filesz) = seg.file_range();
            LoadSegment {
                p_offset,
                p_vaddr: seg.address(),
                p_filesz,
            }
        })
        .collect()
}

/// Parse the unwind info of the ELF at `path`. Convenience wrapper over
/// [`parse_executable`] returning the flat unwind table.
#[cfg(test)]
pub fn build_unwind_tables(path: &Path) -> Result<Vec<UnwindRow>> {
    Ok(parse_executable(path)?.rows)
}

/// Build an executable's flat, PC-sorted unwind table from its `.eh_frame` /
/// `.eh_frame_hdr`. Returns `(fde_count, rows)`, where `fde_count` is the number
/// of functions that contributed rows (informational; see
/// [`ExecutableUnwindInfo::fde_count`]). Returns empty (one-frame unwinding) when
/// either section is missing or the search table is empty.
///
/// The rows of all functions are concatenated in the linker's ascending-PC order;
/// each row's rule applies from its `pc` up to the next row's `pc`. Wherever a
/// function is followed by a gap (or is the last function), an end-of-function
/// stopper row is inserted at the function's end so a PC with no unwind info
/// stops the walk rather than inheriting the previous function's rule.
fn build_from_object(obj: &object::File) -> Result<(u32, Vec<UnwindRow>)> {
    let Some(eh_frame_section) = obj.section_by_name(".eh_frame") else {
        debug!("no .eh_frame section; executable is unwindable to one frame only");
        return Ok((0, Vec::new()));
    };
    let Some(hdr_section) = obj.section_by_name(".eh_frame_hdr") else {
        debug!("no .eh_frame_hdr section; executable is unwindable to one frame only");
        return Ok((0, Vec::new()));
    };
    let eh_frame_data = eh_frame_section
        .uncompressed_data()
        .context("reading .eh_frame")?;
    let hdr_data = hdr_section
        .uncompressed_data()
        .context("reading .eh_frame_hdr")?;
    let endian = if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let mut eh_frame = EhFrame::new(&eh_frame_data, endian);
    eh_frame.set_address_size(8);

    // Section runtime addresses anchor the PC-relative / datarel pointer
    // encodings so both the FDE initial locations and the hdr search table
    // resolve to module virtual addresses (FDE space).
    let mut bases = BaseAddresses::default()
        .set_eh_frame(eh_frame_section.address())
        .set_eh_frame_hdr(hdr_section.address());
    if let Some(s) = obj.section_by_name(".text") {
        bases = bases.set_text(s.address());
    }
    if let Some(s) = obj.section_by_name(".got") {
        bases = bases.set_got(s.address());
    }

    let hdr = EhFrameHdr::new(&hdr_data, endian)
        .parse(&bases, 8)
        .context("parsing .eh_frame_hdr")?;
    let Some(table) = hdr.table() else {
        debug!("empty .eh_frame_hdr search table; executable is unwindable to one frame only");
        return Ok((0, Vec::new()));
    };

    let mut rows: Vec<UnwindRow> = Vec::new();
    let mut ctx = UnwindContext::new();
    let mut fde_count: u32 = 0;
    // End address of the previous function that contributed rows, so a gap before
    // the next function can be bridged with a stopper.
    let mut prev_end: Option<u64> = None;

    // The hdr search table is sorted by initial location (the linker guarantees
    // it), so iterating it yields FDEs already in ascending-PC order. Their
    // ranges don't overlap, so concatenating each function's rows keeps the whole
    // table strictly ascending by pc.
    let mut iter = table.iter(&bases);
    while let Some((_initial_location, fde_ptr)) =
        iter.next().context("iterating .eh_frame_hdr table")?
    {
        // Bound peak memory for a pathological file: stop once we've exceeded the
        // per-executable cap (publish then rejects it, so it unwinds to one frame,
        // matching the previous behaviour) rather than building gigabytes of rows.
        if rows.len() > MAX_ROWS_PER_EXEC as usize {
            break;
        }
        let offset = match table.pointer_to_offset(fde_ptr) {
            Ok(o) => o,
            Err(e) => {
                debug!("skipping unresolvable FDE pointer: {e}");
                continue;
            }
        };
        let fde = match eh_frame.fde_from_offset(&bases, offset, EhFrame::cie_from_offset) {
            Ok(fde) => fde,
            Err(e) => {
                debug!("skipping malformed FDE: {e}");
                continue;
            }
        };
        // A function never spans an i32 of address range, let alone a u32; a
        // zero range carries no instructions. Skip anything outside that.
        let Ok(pc_len) = u32::try_from(fde.len()) else {
            continue;
        };
        if pc_len == 0 {
            continue;
        }
        let pc_begin = fde.initial_address();
        let pc_end = pc_begin.saturating_add(u64::from(pc_len));
        let ra_reg = fde.cie().return_address_register();

        // If this function doesn't start exactly where the previous one ended,
        // the addresses in between have no unwind info: terminate the previous
        // function with a stopper so a PC in the gap stops the walk. Skipped when
        // the previous function already ended in a stopper (it covers the gap).
        if let Some(end) = prev_end
            && end < pc_begin
            && !rows.last().is_some_and(is_stopper)
        {
            rows.push(stopper(end));
        }

        let group_start = rows.len();
        let mut fde_rows = fde
            .rows(&eh_frame, &bases, &mut ctx)
            .context("evaluating FDE rows")?;
        while let Some(row) = fde_rows.next_row().context("evaluating CFI row")? {
            let converted = classify_row(
                row.start_address(),
                row.cfa(),
                &row.register(Register(DW_REG_RBP)),
                &row.register(ra_reg),
            );
            // Collapse a row whose rule set matches the one already in effect
            // within this function; only distinct rules need a row. (Adjacent
            // functions are never collapsed across the boundary, so their ranges
            // stay distinguishable.)
            if rows.len() > group_start && same_rules(&rows[rows.len() - 1], &converted) {
                continue;
            }
            rows.push(converted);
        }

        if rows.len() == group_start {
            continue; // FDE with no rows: leave prev_end so its range stays a gap
        }
        fde_count += 1;
        prev_end = Some(pc_end);
    }

    // Terminate the final function so a PC past all code stops the walk rather
    // than inheriting the last rule.
    if let Some(end) = prev_end
        && !rows.last().is_some_and(is_stopper)
    {
        rows.push(stopper(end));
    }

    Ok((fde_count, rows))
}

/// Convert one evaluated CFI row into our compact representation, or a stopper
/// row if the rules can't be represented (so the walk ends rather than guesses).
fn classify_row<T: ReaderOffset>(
    pc: u64,
    cfa: &CfaRule<T>,
    rbp: &RegisterRule<T>,
    ra: &RegisterRule<T>,
) -> UnwindRow {
    // The return address must be the standard `*(CFA - 8)`.
    if !matches!(ra, RegisterRule::Offset(o) if *o == -ADDR_SIZE) {
        return stopper(pc);
    }

    let (cfa_type, cfa_offset) = match cfa {
        CfaRule::RegisterAndOffset { register, offset } => {
            let ty = match register.0 {
                DW_REG_RSP => CfaType::CFA_RSP,
                DW_REG_RBP => CfaType::CFA_RBP,
                _ => return stopper(pc),
            };
            match i16::try_from(*offset) {
                Ok(off) => (ty, off),
                // Frame larger than an i16 CFA offset can hold (rare).
                Err(_) => return stopper(pc),
            }
        }
        CfaRule::Expression(_) => return stopper(pc),
    };

    let (rbp_type, rbp_offset) = match rbp {
        RegisterRule::Offset(o) => match i16::try_from(*o) {
            Ok(off) => (RbpRule::RBP_CFA_OFFSET, off),
            Err(_) => return stopper(pc),
        },
        // rbp is callee-saved: if the CFI never relocates it, the caller's value
        // is whatever we currently hold.
        RegisterRule::SameValue | RegisterRule::Undefined => (RbpRule::RBP_UNCHANGED, 0),
        _ => return stopper(pc),
    };

    UnwindRow {
        pc,
        cfa_offset,
        rbp_offset,
        cfa_type: cfa_type as u8,
        rbp_type: rbp_type as u8,
        _pad: 0,
    }
}

/// A row that ends unwinding at `pc`: emitted for an unrepresentable CFI rule, or
/// at a function's end before a gap, so the walk stops there rather than guessing.
fn stopper(pc: u64) -> UnwindRow {
    UnwindRow {
        pc,
        cfa_offset: 0,
        rbp_offset: 0,
        cfa_type: CfaType::CFA_UNSUPPORTED as u8,
        rbp_type: RbpRule::RBP_UNSUPPORTED as u8,
        _pad: 0,
    }
}

/// Whether `row` is a stopper (an `CFA_UNSUPPORTED` row that ends the walk).
fn is_stopper(row: &UnwindRow) -> bool {
    row.cfa_type == CfaType::CFA_UNSUPPORTED as u8
}

fn same_rules(a: &UnwindRow, b: &UnwindRow) -> bool {
    a.cfa_type == b.cfa_type
        && a.cfa_offset == b.cfa_offset
        && a.rbp_type == b.rbp_type
        && a.rbp_offset == b.rbp_offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_flat_unwind_table_for_self() {
        // The test binary is an ELF with .eh_frame + .eh_frame_hdr, so this
        // exercises the whole hdr-iterate → parse → classify → flatten pipeline on
        // real DWARF.
        let rows = build_unwind_tables(Path::new("/proc/self/exe")).expect("build tables");
        assert!(!rows.is_empty(), "test binary should yield unwind rows");

        // The flat table is one array in the linker's ascending-PC function order;
        // within a function rows ascend by pc and function ranges don't overlap, so
        // the whole table is strictly increasing by pc and binary-searchable.
        for w in rows.windows(2) {
            assert!(
                w[0].pc < w[1].pc,
                "rows must be strictly ascending by pc across the whole table"
            );
        }

        // Optimized code without frame pointers is dominated by rsp-relative CFA.
        assert!(
            rows.iter().any(|r| r.cfa_type == CfaType::CFA_RSP as u8),
            "expected rsp-based CFA rows"
        );
        // At least one real (non-stopper) rule must be present...
        assert!(
            rows.iter().any(|r| !is_stopper(r)),
            "expected real (non-stopper) rows"
        );
        // ...and the table must end with a stopper, so a PC past the last function
        // stops the walk rather than inheriting its final rule.
        assert!(
            is_stopper(rows.last().unwrap()),
            "the flat table must end with a stopper row"
        );
    }

    #[test]
    fn same_rules_compares_the_rule_set_not_the_pc() {
        let row = |pc, off| UnwindRow {
            pc,
            cfa_offset: off,
            rbp_offset: 0,
            cfa_type: CfaType::CFA_RSP as u8,
            rbp_type: RbpRule::RBP_UNCHANGED as u8,
            _pad: 0,
        };
        // Same rule at different PCs collapses; a different CFA offset does not,
        // and a stopper never matches a real rule.
        assert!(same_rules(&row(0x10, 8), &row(0x20, 8)));
        assert!(!same_rules(&row(0x10, 8), &row(0x20, 16)));
        assert!(!same_rules(&row(0x10, 8), &stopper(0x20)));
    }
}
