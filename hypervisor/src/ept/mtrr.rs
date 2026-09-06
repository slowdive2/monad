extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use x86::msr::{
    IA32_MTRRCAP, IA32_MTRR_DEF_TYPE, IA32_MTRR_FIX16K_80000, IA32_MTRR_FIX16K_A0000,
    IA32_MTRR_FIX4K_C0000, IA32_MTRR_FIX64K_00000, IA32_MTRR_PHYSBASE0, IA32_MTRR_PHYSMASK0,
};

use crate::arch::intel::state::read_msr;

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{EptMemoryType, PAGE_SIZE_4K};

const MTRR_ENABLE: u64 = 1 << 11;
const FIXED_ENABLE: u64 = 1 << 10;
const FIXED_SUPPORTED: u64 = 1 << 8;
const VARIABLE_VALID: u64 = 1 << 11;
pub const MAX_VARIABLE_MTRRS: u8 = 40;
const FIXED_REGISTER_COUNT: usize = 11;

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtrrErrorDetail {
    Disabled = 1,
    InvalidDefaultType = 2,
    InvalidVariableCount = 3,
    FixedUnsupported = 4,
    InvalidFixedType = 5,
    InvalidVariableType = 6,
    InvalidVariableMask = 7,
    MisalignedVariableRange = 8,
    VariableRangeOverflow = 9,
    UnsupportedOverlap = 10,
    IncompleteCover = 11,
    InvalidAperture = 12,
    AllocationFailure = 13,
}

fn mtrr_error(detail: MtrrErrorDetail) -> MonadError {
    let code = if detail == MtrrErrorDetail::AllocationFailure {
        ErrorCode::AllocationFailure
    } else {
        ErrorCode::UnsupportedMtrrCombination
    };
    MonadError::new(ErrorPhase::Mtrr, code, detail as u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawVariableMtrr {
    pub base: u64,
    pub mask: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMtrrState {
    pub capability: u64,
    pub default_type: u64,
    pub fixed: [u64; FIXED_REGISTER_COUNT],
    pub variable: Box<[RawVariableMtrr]>,
    pub max_physical_bits: u8,
}

pub fn collect_raw_mtrr_state(max_physical_bits: u8) -> MonadResult<RawMtrrState> {
    let capability = read_msr(IA32_MTRRCAP);
    let variable_count = (capability & 0xff) as usize;
    // Variable MSRs must not overlap the fixed-register range at 0x250.
    if variable_count > usize::from(MAX_VARIABLE_MTRRS) || capability & FIXED_SUPPORTED == 0 {
        return Err(mtrr_error(MtrrErrorDetail::InvalidVariableCount));
    }
    let mut variable = Vec::new();
    variable.try_reserve_exact(variable_count).map_err(|_| {
        MonadError::new(
            ErrorPhase::Mtrr,
            ErrorCode::AllocationFailure,
            variable_count as u64,
        )
    })?;
    for index in 0..variable_count as u32 {
        variable.push(RawVariableMtrr {
            base: read_msr(IA32_MTRR_PHYSBASE0 + index * 2),
            mask: read_msr(IA32_MTRR_PHYSMASK0 + index * 2),
        });
    }
    let mut fixed = [0u64; FIXED_REGISTER_COUNT];
    fixed[0] = read_msr(IA32_MTRR_FIX64K_00000);
    fixed[1] = read_msr(IA32_MTRR_FIX16K_80000);
    fixed[2] = read_msr(IA32_MTRR_FIX16K_A0000);
    for index in 0..8u32 {
        fixed[3 + index as usize] = read_msr(IA32_MTRR_FIX4K_C0000 + index);
    }
    Ok(RawMtrrState {
        capability,
        default_type: read_msr(IA32_MTRR_DEF_TYPE),
        fixed,
        variable: variable.into_boxed_slice(),
        max_physical_bits,
    })
}

impl RawMtrrState {
    /// Allocation-free revalidation; called by every CPU before any CPU enters VMX.
    pub fn matches_registers(&self, mut read: impl FnMut(u32) -> u64) -> bool {
        if read(IA32_MTRRCAP) != self.capability || read(IA32_MTRR_DEF_TYPE) != self.default_type {
            return false;
        }
        let fixed_msrs = [
            0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f,
        ];
        fixed_msrs
            .iter()
            .zip(self.fixed)
            .all(|(&msr, value)| read(msr) == value)
            && self.variable.iter().enumerate().all(|(index, value)| {
                read(IA32_MTRR_PHYSBASE0 + index as u32 * 2) == value.base
                    && read(IA32_MTRR_PHYSMASK0 + index as u32 * 2) == value.mask
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryTypeInterval {
    pub start: u64,
    pub end_exclusive: u64,
    pub memory_type: EptMemoryType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedMemoryMap {
    intervals: Box<[MemoryTypeInterval]>,
    aperture_end: u64,
}

impl NormalizedMemoryMap {
    pub fn from_intervals(
        intervals: &[MemoryTypeInterval],
        aperture_end: u64,
    ) -> MonadResult<Self> {
        let exact = aperture_end != 0
            && aperture_end & (PAGE_SIZE_4K - 1) == 0
            && intervals.first().is_some_and(|first| first.start == 0)
            && intervals
                .last()
                .is_some_and(|last| last.end_exclusive == aperture_end)
            && intervals.iter().all(|interval| {
                interval.start < interval.end_exclusive
                    && interval.start & (PAGE_SIZE_4K - 1) == 0
                    && interval.end_exclusive & (PAGE_SIZE_4K - 1) == 0
            })
            && intervals.windows(2).all(|pair| {
                pair[0].end_exclusive == pair[1].start && pair[0].memory_type != pair[1].memory_type
            });
        if !exact {
            return Err(mtrr_error(MtrrErrorDetail::IncompleteCover));
        }
        let mut owned = Vec::new();
        reserve(&mut owned, intervals.len())?;
        owned.extend_from_slice(intervals);
        Ok(Self {
            intervals: owned.into_boxed_slice(),
            aperture_end,
        })
    }

    pub fn intervals(&self) -> &[MemoryTypeInterval] {
        &self.intervals
    }

    pub const fn aperture_end(&self) -> u64 {
        self.aperture_end
    }

    pub fn memory_type_at(&self, address: u64) -> Option<EptMemoryType> {
        self.intervals
            .iter()
            .find(|interval| interval.start <= address && address < interval.end_exclusive)
            .map(|interval| interval.memory_type)
    }

    pub fn uniform_type(&self, start: u64, end_exclusive: u64) -> Option<EptMemoryType> {
        if start >= end_exclusive {
            return None;
        }
        self.intervals
            .iter()
            .find(|interval| interval.start <= start && end_exclusive <= interval.end_exclusive)
            .map(|interval| interval.memory_type)
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodedRange {
    start: u64,
    end_exclusive: u64,
    memory_type: EptMemoryType,
    fixed: bool,
}

fn reserve<T>(values: &mut Vec<T>, additional: usize) -> MonadResult<()> {
    values
        .try_reserve(additional)
        .map_err(|_| mtrr_error(MtrrErrorDetail::AllocationFailure))
}

fn physical_mask(bits: u8) -> MonadResult<u64> {
    if !(12..=48).contains(&bits) {
        return Err(mtrr_error(MtrrErrorDetail::InvalidVariableMask));
    }
    Ok(((1u64 << bits) - 1) & !(PAGE_SIZE_4K - 1))
}

fn decode_type(value: u64, detail: MtrrErrorDetail) -> MonadResult<EptMemoryType> {
    EptMemoryType::try_from((value & 0xff) as u8).map_err(|_| mtrr_error(detail))
}

fn push_fixed_register(
    ranges: &mut Vec<DecodedRange>,
    value: u64,
    start: u64,
    length: u64,
) -> MonadResult<()> {
    reserve(ranges, 8)?;
    for index in 0..8u64 {
        ranges.push(DecodedRange {
            start: start + index * length,
            end_exclusive: start + (index + 1) * length,
            memory_type: decode_type(value >> (index * 8), MtrrErrorDetail::InvalidFixedType)?,
            fixed: true,
        });
    }
    Ok(())
}

fn decode_ranges(raw: &RawMtrrState) -> MonadResult<(EptMemoryType, Vec<DecodedRange>)> {
    if raw.default_type & MTRR_ENABLE == 0 {
        return Err(mtrr_error(MtrrErrorDetail::Disabled));
    }
    if raw.default_type & !(MTRR_ENABLE | FIXED_ENABLE | 0xff) != 0 {
        return Err(mtrr_error(MtrrErrorDetail::InvalidDefaultType));
    }
    let default_type = decode_type(raw.default_type, MtrrErrorDetail::InvalidDefaultType)?;
    let variable_count = (raw.capability & 0xff) as usize;
    if raw.variable.len() != variable_count {
        return Err(mtrr_error(MtrrErrorDetail::InvalidVariableCount));
    }

    let fixed_enabled = raw.default_type & FIXED_ENABLE != 0;
    if fixed_enabled && raw.capability & FIXED_SUPPORTED == 0 {
        return Err(mtrr_error(MtrrErrorDetail::FixedUnsupported));
    }

    let mut ranges = Vec::new();
    reserve(
        &mut ranges,
        variable_count + usize::from(fixed_enabled) * 88,
    )?;
    if fixed_enabled {
        push_fixed_register(&mut ranges, raw.fixed[0], 0, 0x1_0000)?;
        push_fixed_register(&mut ranges, raw.fixed[1], 0x8_0000, 0x4000)?;
        push_fixed_register(&mut ranges, raw.fixed[2], 0xa_0000, 0x4000)?;
        for index in 0..8usize {
            push_fixed_register(
                &mut ranges,
                raw.fixed[3 + index],
                0xc_0000 + index as u64 * 0x8_000,
                0x1000,
            )?;
        }
    }

    let address_mask = physical_mask(raw.max_physical_bits)?;
    let architectural_limit = 1u64 << raw.max_physical_bits;
    let width_mask = architectural_limit - 1;
    for value in raw.variable.iter().copied() {
        if value.mask & VARIABLE_VALID == 0 {
            continue;
        }
        if value.base & !(address_mask | 0xff) != 0
            || value.base & 0xf00 != 0
            || value.mask & !(address_mask | VARIABLE_VALID) != 0
        {
            return Err(mtrr_error(MtrrErrorDetail::InvalidVariableMask));
        }
        let memory_type = decode_type(value.base, MtrrErrorDetail::InvalidVariableType)?;
        let mask = value.mask & address_mask;
        let size = ((!mask) & width_mask)
            .checked_add(1)
            .ok_or_else(|| mtrr_error(MtrrErrorDetail::VariableRangeOverflow))?;
        if size < PAGE_SIZE_4K || !size.is_power_of_two() || mask != address_mask & !(size - 1) {
            return Err(mtrr_error(MtrrErrorDetail::InvalidVariableMask));
        }
        let start = value.base & address_mask;
        if start & (size - 1) != 0 {
            return Err(mtrr_error(MtrrErrorDetail::MisalignedVariableRange));
        }
        let end_exclusive = start
            .checked_add(size)
            .ok_or_else(|| mtrr_error(MtrrErrorDetail::VariableRangeOverflow))?;
        if end_exclusive > architectural_limit {
            return Err(mtrr_error(MtrrErrorDetail::VariableRangeOverflow));
        }
        ranges.push(DecodedRange {
            start,
            end_exclusive,
            memory_type,
            fixed: false,
        });
    }
    Ok((default_type, ranges))
}

fn resolve_variable_type(
    ranges: &[DecodedRange],
    start: u64,
    end_exclusive: u64,
    default_type: EptMemoryType,
) -> MonadResult<EptMemoryType> {
    let mut type_mask = 0u8;
    for range in ranges.iter().filter(|range| {
        !range.fixed && range.start <= start && end_exclusive <= range.end_exclusive
    }) {
        type_mask |= 1 << range.memory_type as u8;
    }
    if type_mask == 0 {
        return Ok(default_type);
    }
    if type_mask & (1 << EptMemoryType::Uncacheable as u8) != 0 {
        return Ok(EptMemoryType::Uncacheable);
    }
    if type_mask.count_ones() == 1 {
        return EptMemoryType::try_from(type_mask.trailing_zeros() as u8)
            .map_err(|_| mtrr_error(MtrrErrorDetail::UnsupportedOverlap));
    }
    let wb_wt = (1 << EptMemoryType::WriteBack as u8) | (1 << EptMemoryType::WriteThrough as u8);
    if type_mask == wb_wt {
        return Ok(EptMemoryType::WriteThrough);
    }
    Err(mtrr_error(MtrrErrorDetail::UnsupportedOverlap))
}

pub fn normalize_mtrrs(raw: &RawMtrrState, aperture_end: u64) -> MonadResult<NormalizedMemoryMap> {
    let architectural_limit = 1u64
        .checked_shl(u32::from(raw.max_physical_bits))
        .ok_or_else(|| mtrr_error(MtrrErrorDetail::InvalidAperture))?;
    if aperture_end == 0
        || aperture_end & (PAGE_SIZE_4K - 1) != 0
        || aperture_end > architectural_limit
    {
        return Err(mtrr_error(MtrrErrorDetail::InvalidAperture));
    }
    let (default_type, ranges) = decode_ranges(raw)?;

    let mut boundaries = Vec::new();
    reserve(&mut boundaries, 2 + ranges.len() * 2)?;
    boundaries.push(0);
    boundaries.push(aperture_end);
    for range in &ranges {
        let start = range.start.min(aperture_end);
        let end = range.end_exclusive.min(aperture_end);
        if start < end {
            boundaries.push(start);
            boundaries.push(end);
        }
    }
    boundaries.sort_unstable();
    boundaries.dedup();

    let mut intervals: Vec<MemoryTypeInterval> = Vec::new();
    reserve(&mut intervals, boundaries.len().saturating_sub(1))?;
    for pair in boundaries.windows(2) {
        let start = pair[0];
        let end_exclusive = pair[1];
        if start == end_exclusive {
            continue;
        }
        let fixed = ranges.iter().find(|range| {
            range.fixed && range.start <= start && end_exclusive <= range.end_exclusive
        });
        let memory_type = if let Some(range) = fixed {
            range.memory_type
        } else {
            resolve_variable_type(&ranges, start, end_exclusive, default_type)?
        };
        if let Some(previous) = intervals.last_mut() {
            if previous.end_exclusive == start && previous.memory_type == memory_type {
                previous.end_exclusive = end_exclusive;
                continue;
            }
        }
        intervals.push(MemoryTypeInterval {
            start,
            end_exclusive,
            memory_type,
        });
    }

    let exact = intervals.first().is_some_and(|first| first.start == 0)
        && intervals
            .last()
            .is_some_and(|last| last.end_exclusive == aperture_end)
        && intervals
            .windows(2)
            .all(|pair| pair[0].end_exclusive == pair[1].start);
    if !exact {
        return Err(mtrr_error(MtrrErrorDetail::IncompleteCover));
    }
    NormalizedMemoryMap::from_intervals(&intervals, aperture_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeated_type(memory_type: EptMemoryType) -> u64 {
        u64::from_le_bytes([memory_type as u8; 8])
    }

    fn raw(variable: &[RawVariableMtrr]) -> RawMtrrState {
        RawMtrrState {
            capability: variable.len() as u64,
            default_type: MTRR_ENABLE | EptMemoryType::WriteBack as u64,
            fixed: [repeated_type(EptMemoryType::WriteBack); FIXED_REGISTER_COUNT],
            variable: variable.into(),
            max_physical_bits: 48,
        }
    }

    fn variable(start: u64, size: u64, memory_type: EptMemoryType) -> RawVariableMtrr {
        let address_mask = physical_mask(48).expect("physical mask");
        RawVariableMtrr {
            base: start | memory_type as u64,
            mask: (address_mask & !(size - 1)) | VARIABLE_VALID,
        }
    }

    #[test]
    fn mtrr_fixed_precedence() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let mut state = raw(&[variable(0, 0x20_0000, EptMemoryType::WriteCombining)]);
        state.capability |= FIXED_SUPPORTED;
        state.default_type |= FIXED_ENABLE;
        state.fixed[2] = repeated_type(EptMemoryType::Uncacheable);
        let map = normalize_mtrrs(&state, 0x20_0000).expect("normalized map");
        assert_eq!(
            map.memory_type_at(0xa_0000),
            Some(EptMemoryType::Uncacheable)
        );
        assert_eq!(
            map.memory_type_at(0x10_0000),
            Some(EptMemoryType::WriteCombining)
        );
    }

    #[test]
    fn mtrr_uc_dominance() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let state = raw(&[
            variable(0, 0x40_0000, EptMemoryType::WriteBack),
            variable(0x20_0000, 0x20_0000, EptMemoryType::Uncacheable),
        ]);
        let map = normalize_mtrrs(&state, 0x40_0000).expect("uc overlap");
        assert_eq!(
            map.memory_type_at(0x30_0000),
            Some(EptMemoryType::Uncacheable)
        );
    }

    #[test]
    fn mtrr_wb_wt() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let state = raw(&[
            variable(0, 0x40_0000, EptMemoryType::WriteBack),
            variable(0x20_0000, 0x20_0000, EptMemoryType::WriteThrough),
        ]);
        let map = normalize_mtrrs(&state, 0x40_0000).expect("wb and wt overlap");
        assert_eq!(
            map.memory_type_at(0x30_0000),
            Some(EptMemoryType::WriteThrough)
        );
    }

    #[test]
    fn mtrr_unsupported_mix() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let state = raw(&[
            variable(0, 0x40_0000, EptMemoryType::WriteBack),
            variable(0x20_0000, 0x20_0000, EptMemoryType::WriteCombining),
        ]);
        let error = normalize_mtrrs(&state, 0x40_0000).expect_err("unsupported overlap");
        assert_eq!(error.code, ErrorCode::UnsupportedMtrrCombination);
        assert_eq!(error.detail, MtrrErrorDetail::UnsupportedOverlap as u64);
    }

    #[test]
    fn mtrr_exact_cover() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let map = normalize_mtrrs(&raw(&[]), 0x80_0000).expect("default cover");
        assert_eq!(
            map.intervals(),
            &[MemoryTypeInterval {
                start: 0,
                end_exclusive: 0x80_0000,
                memory_type: EptMemoryType::WriteBack,
            }]
        );

        let mut disabled = raw(&[]);
        disabled.default_type &= !MTRR_ENABLE;
        assert!(normalize_mtrrs(&disabled, 0x80_0000).is_err());

        let malformed = raw(&[RawVariableMtrr {
            base: 0x10_0000 | EptMemoryType::WriteBack as u64,
            mask: (physical_mask(48).expect("mask") & !(0x20_0000 - 1)) | VARIABLE_VALID,
        }]);
        assert!(normalize_mtrrs(&malformed, 0x80_0000).is_err());

        let mut reserved_default = raw(&[]);
        reserved_default.default_type |= 1 << 63;
        let error =
            normalize_mtrrs(&reserved_default, 0x80_0000).expect_err("reserved default-type bits");
        assert_eq!(error.detail, MtrrErrorDetail::InvalidDefaultType as u64);

        let first = MemoryTypeInterval {
            start: 0,
            end_exclusive: PAGE_SIZE_4K,
            memory_type: EptMemoryType::WriteBack,
        };
        let gap = MemoryTypeInterval {
            start: PAGE_SIZE_4K * 2,
            end_exclusive: PAGE_SIZE_4K * 3,
            memory_type: EptMemoryType::Uncacheable,
        };
        assert!(NormalizedMemoryMap::from_intervals(&[first, gap], PAGE_SIZE_4K * 3).is_err());
        let overlap = MemoryTypeInterval {
            start: 0,
            end_exclusive: PAGE_SIZE_4K * 2,
            memory_type: EptMemoryType::Uncacheable,
        };
        assert!(NormalizedMemoryMap::from_intervals(&[overlap, first], PAGE_SIZE_4K * 2).is_err());
        let same = MemoryTypeInterval {
            start: PAGE_SIZE_4K,
            end_exclusive: PAGE_SIZE_4K * 2,
            memory_type: EptMemoryType::WriteBack,
        };
        assert!(NormalizedMemoryMap::from_intervals(&[first, same], PAGE_SIZE_4K * 2).is_err());
    }
    #[test]
    fn launch_snapshot_and_interception_cover_every_admitted_register() {
        for count in [0u8, 4, 8, 10, MAX_VARIABLE_MTRRS] {
            let state = RawMtrrState {
                capability: FIXED_SUPPORTED | u64::from(count),
                default_type: 0xc06,
                fixed: [0; FIXED_REGISTER_COUNT],
                variable: alloc::vec![RawVariableMtrr { base: 0, mask: 0 }; usize::from(count)]
                    .into_boxed_slice(),
                max_physical_bits: 48,
            };
            let read = |msr| match msr {
                IA32_MTRRCAP => state.capability,
                IA32_MTRR_DEF_TYPE => state.default_type,
                _ => 0,
            };
            assert!(state.matches_registers(read));
            for msr in (0x200..0x200 + u32::from(count) * 2).chain([
                0x250, 0x258, 0x259, 0x268, 0x269, 0x26a, 0x26b, 0x26c, 0x26d, 0x26e, 0x26f, 0x2ff,
            ]) {
                assert!(crate::exit::msr::is_mtrr_write(msr, count));
                assert!(!state.matches_registers(|field| read(field) ^ u64::from(field == msr)));
            }
            assert!(
                !crate::exit::msr::is_mtrr_write(0x200 + u32::from(count) * 2, count)
                    || count == MAX_VARIABLE_MTRRS
            );
        }
    }
}
