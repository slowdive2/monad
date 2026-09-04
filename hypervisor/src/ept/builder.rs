extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{
    entry::{EptPdEntry, EptPdptEntry, EptPml4Entry, EptPtEntry},
    walker::{verify_view, ViewVerification},
    EptLeafSize, EptLevel, EptPageAllocator, EptPageKind, EptPageOwner, EptPageStore,
    EptPermissions, GuestPhysicalAddress, HostPhysicalAddress, NormalizedMemoryMap, ViewId,
    PAGE_SIZE_4K,
};

const SIZE_1G: u64 = EptLeafSize::Size1G as u64;
const SIZE_2M: u64 = EptLeafSize::Size2M as u64;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalRangeKind {
    Memory = 1,
    Device = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRange {
    pub start: u64,
    pub length: u64,
    pub kind: PhysicalRangeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredPhysicalRange {
    pub start: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryInterval {
    pub start: u64,
    pub end_exclusive: u64,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApertureErrorDetail {
    EmptyInventory = 1,
    ZeroLength = 2,
    RangeOverflow = 3,
    InvalidConfiguredLimit = 4,
    MissingRequiredRange = 5,
    RequiredRangeBeyondLimit = 6,
    RoundingOverflow = 7,
    AllocationFailure = 8,
}

fn aperture_error(code: ErrorCode, detail: ApertureErrorDetail) -> MonadError {
    MonadError::new(ErrorPhase::EptBuild, code, detail as u64)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalInventory {
    ranges: Box<[InventoryInterval]>,
    aperture_end: u64,
    architectural_limit: u64,
}

impl PhysicalInventory {
    pub fn ingest(
        inventory: &[PhysicalRange],
        required: &[RequiredPhysicalRange],
        max_physical_bits: u8,
        configured_limit: Option<u64>,
    ) -> MonadResult<Self> {
        if inventory.is_empty() {
            return Err(aperture_error(
                ErrorCode::InvalidRange,
                ApertureErrorDetail::EmptyInventory,
            ));
        }
        if max_physical_bits == 0 || max_physical_bits >= 64 {
            return Err(aperture_error(
                ErrorCode::PhysicalAddressTooWide,
                ApertureErrorDetail::InvalidConfiguredLimit,
            ));
        }
        let architectural_limit = 1u64 << max_physical_bits.min(48);
        let configured_limit = configured_limit.unwrap_or(architectural_limit);
        if configured_limit == 0
            || configured_limit & (PAGE_SIZE_4K - 1) != 0
            || configured_limit > architectural_limit
        {
            return Err(aperture_error(
                ErrorCode::InvalidRange,
                ApertureErrorDetail::InvalidConfiguredLimit,
            ));
        }

        let mut ranges = Vec::new();
        ranges.try_reserve(inventory.len()).map_err(|_| {
            aperture_error(
                ErrorCode::AllocationFailure,
                ApertureErrorDetail::AllocationFailure,
            )
        })?;
        for range in inventory {
            if range.length == 0 {
                return Err(aperture_error(
                    ErrorCode::InvalidRange,
                    ApertureErrorDetail::ZeroLength,
                ));
            }
            let end_exclusive = range.start.checked_add(range.length).ok_or_else(|| {
                aperture_error(
                    ErrorCode::AddressOverflow,
                    ApertureErrorDetail::RangeOverflow,
                )
            })?;
            ranges.push(InventoryInterval {
                start: range.start,
                end_exclusive,
            });
        }
        ranges.sort_unstable_by_key(|range| range.start);

        let mut merged: Vec<InventoryInterval> = Vec::new();
        merged.try_reserve(ranges.len()).map_err(|_| {
            aperture_error(
                ErrorCode::AllocationFailure,
                ApertureErrorDetail::AllocationFailure,
            )
        })?;
        for range in ranges {
            if let Some(previous) = merged.last_mut() {
                if range.start <= previous.end_exclusive {
                    previous.end_exclusive = previous.end_exclusive.max(range.end_exclusive);
                    continue;
                }
            }
            merged.push(range);
        }

        for wanted in required {
            if wanted.length == 0 {
                return Err(aperture_error(
                    ErrorCode::InvalidRange,
                    ApertureErrorDetail::ZeroLength,
                ));
            }
            let wanted_end = wanted.start.checked_add(wanted.length).ok_or_else(|| {
                aperture_error(
                    ErrorCode::AddressOverflow,
                    ApertureErrorDetail::RangeOverflow,
                )
            })?;
            if !merged
                .iter()
                .any(|range| range.start <= wanted.start && wanted_end <= range.end_exclusive)
            {
                return Err(aperture_error(
                    ErrorCode::InvalidRange,
                    ApertureErrorDetail::MissingRequiredRange,
                ));
            }
        }

        let highest_required_end = merged
            .iter()
            .map(|range| range.end_exclusive)
            .max()
            .ok_or_else(|| {
                aperture_error(ErrorCode::InvalidRange, ApertureErrorDetail::EmptyInventory)
            })?;
        if highest_required_end > configured_limit {
            return Err(aperture_error(
                ErrorCode::PhysicalAddressTooWide,
                ApertureErrorDetail::RequiredRangeBeyondLimit,
            ));
        }
        let rounded = highest_required_end
            .checked_add(SIZE_1G - 1)
            .map(|value| value & !(SIZE_1G - 1))
            .ok_or_else(|| {
                aperture_error(
                    ErrorCode::AddressOverflow,
                    ApertureErrorDetail::RoundingOverflow,
                )
            })?;
        let aperture_end = rounded.min(configured_limit);
        if aperture_end < highest_required_end || aperture_end & (PAGE_SIZE_4K - 1) != 0 {
            return Err(aperture_error(
                ErrorCode::PhysicalAddressTooWide,
                ApertureErrorDetail::RequiredRangeBeyondLimit,
            ));
        }
        Ok(Self {
            ranges: merged.into_boxed_slice(),
            aperture_end,
            architectural_limit,
        })
    }

    pub fn ranges(&self) -> &[InventoryInterval] {
        &self.ranges
    }

    pub const fn aperture_end(&self) -> u64 {
        self.aperture_end
    }

    pub const fn architectural_limit(&self) -> u64 {
        self.architectural_limit
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseViewMetadata {
    pub table_pages: u32,
    pub leaf_1g: u32,
    pub leaf_2m: u32,
    pub leaf_4k: u32,
    pub mapped_pages_4k: u64,
}

pub(super) struct BaseViewCandidate<A: EptPageAllocator> {
    pub(super) root: HostPhysicalAddress,
    pub(super) pages: EptPageStore<A>,
    pub(super) inventory: PhysicalInventory,
    pub(super) memory_types: NormalizedMemoryMap,
    pub(super) max_physical_bits: u8,
    pub(super) execute_only_supported: bool,
}

pub struct VerifiedBaseView<A: EptPageAllocator> {
    candidate: BaseViewCandidate<A>,
    metadata: BaseViewMetadata,
}

impl<A: EptPageAllocator> VerifiedBaseView<A> {
    pub const fn id(&self) -> ViewId {
        ViewId {
            slot: 0,
            reserved: 0,
            generation: 1,
        }
    }

    pub const fn aperture_end(&self) -> u64 {
        self.candidate.inventory.aperture_end
    }

    pub const fn metadata(&self) -> BaseViewMetadata {
        self.metadata
    }

    pub fn walk(&self, gpa: GuestPhysicalAddress) -> super::WalkResult {
        super::walker::walk(&self.candidate, gpa)
    }

    pub(super) fn into_candidate(self) -> BaseViewCandidate<A> {
        self.candidate
    }
}

fn build_error(detail: u64) -> MonadError {
    MonadError::new(
        ErrorPhase::EptBuild,
        ErrorCode::EptVerificationFailure,
        detail,
    )
}

fn table_kind(level: EptLevel) -> EptPageKind {
    match level {
        EptLevel::Pml4 => EptPageKind::Pml4,
        EptLevel::Pdpt => EptPageKind::Pdpt,
        EptLevel::Pd => EptPageKind::Pd,
        EptLevel::Pt => EptPageKind::Pt,
    }
}

struct BuildRules<'a> {
    aperture_end: u64,
    memory_types: &'a NormalizedMemoryMap,
    max_physical_bits: u8,
    page_1g_supported: bool,
    page_2m_supported: bool,
    permissions: EptPermissions,
}

fn build_table<A: EptPageAllocator>(
    pages: &mut EptPageStore<A>,
    level: EptLevel,
    table_base: u64,
    rules: &BuildRules<'_>,
) -> MonadResult<HostPhysicalAddress> {
    let table = pages.allocate(table_kind(level), EptPageOwner::BaseBuild)?;
    let span = match level {
        EptLevel::Pml4 => 1u64 << 39,
        EptLevel::Pdpt => SIZE_1G,
        EptLevel::Pd => SIZE_2M,
        EptLevel::Pt => PAGE_SIZE_4K,
    };
    for index in 0..512usize {
        let entry_base = table_base
            .checked_add(index as u64 * span)
            .ok_or_else(|| build_error(table_base))?;
        if entry_base >= rules.aperture_end {
            break;
        }
        let entry_end = entry_base
            .checked_add(span)
            .ok_or_else(|| build_error(entry_base))?;
        let raw = match level {
            EptLevel::Pml4 => {
                let child = build_table(pages, EptLevel::Pdpt, entry_base, rules)?;
                EptPml4Entry::new_table(child, rules.max_physical_bits)?.raw()
            }
            EptLevel::Pdpt
                if rules.page_1g_supported
                    && entry_end <= rules.aperture_end
                    && rules
                        .memory_types
                        .uniform_type(entry_base, entry_end)
                        .is_some() =>
            {
                let memory_type = rules
                    .memory_types
                    .uniform_type(entry_base, entry_end)
                    .ok_or_else(|| build_error(entry_base))?;
                let hpa = HostPhysicalAddress::for_mapping(
                    entry_base,
                    SIZE_1G,
                    SIZE_1G,
                    rules.max_physical_bits,
                )?;
                EptPdptEntry::new_1g_leaf(
                    hpa,
                    rules.permissions,
                    memory_type,
                    rules.max_physical_bits,
                )?
                .raw()
            }
            EptLevel::Pdpt => {
                let child = build_table(pages, EptLevel::Pd, entry_base, rules)?;
                EptPdptEntry::new_table(child, rules.max_physical_bits)?.raw()
            }
            EptLevel::Pd
                if rules.page_2m_supported
                    && entry_end <= rules.aperture_end
                    && rules
                        .memory_types
                        .uniform_type(entry_base, entry_end)
                        .is_some() =>
            {
                let memory_type = rules
                    .memory_types
                    .uniform_type(entry_base, entry_end)
                    .ok_or_else(|| build_error(entry_base))?;
                let hpa = HostPhysicalAddress::for_mapping(
                    entry_base,
                    SIZE_2M,
                    SIZE_2M,
                    rules.max_physical_bits,
                )?;
                EptPdEntry::new_2m_leaf(
                    hpa,
                    rules.permissions,
                    memory_type,
                    rules.max_physical_bits,
                )?
                .raw()
            }
            EptLevel::Pd => {
                let child = build_table(pages, EptLevel::Pt, entry_base, rules)?;
                EptPdEntry::new_table(child, rules.max_physical_bits)?.raw()
            }
            EptLevel::Pt => {
                if entry_end > rules.aperture_end {
                    return Err(build_error(entry_base));
                }
                let memory_type = rules
                    .memory_types
                    .uniform_type(entry_base, entry_end)
                    .ok_or_else(|| build_error(entry_base))?;
                let hpa = HostPhysicalAddress::for_mapping(
                    entry_base,
                    PAGE_SIZE_4K,
                    PAGE_SIZE_4K,
                    rules.max_physical_bits,
                )?;
                EptPtEntry::new_4k_leaf(
                    hpa,
                    rules.permissions,
                    memory_type,
                    rules.max_physical_bits,
                )?
                .raw()
            }
        };
        pages.write_entry(table, index, raw)?;
    }
    Ok(table)
}

pub(super) fn build_candidate<A: EptPageAllocator>(
    allocator: A,
    inventory: PhysicalInventory,
    memory_types: NormalizedMemoryMap,
    max_physical_bits: u8,
    page_1g_supported: bool,
    page_2m_supported: bool,
    execute_only_supported: bool,
) -> MonadResult<BaseViewCandidate<A>> {
    if inventory.aperture_end != memory_types.aperture_end()
        || inventory.aperture_end > inventory.architectural_limit
    {
        return Err(build_error(inventory.aperture_end));
    }
    let mut pages = EptPageStore::new(allocator, max_physical_bits)?;
    let permissions = EptPermissions::new(true, true, true, execute_only_supported)?;
    let rules = BuildRules {
        aperture_end: inventory.aperture_end,
        memory_types: &memory_types,
        max_physical_bits,
        page_1g_supported,
        page_2m_supported,
        permissions,
    };
    let root = build_table(&mut pages, EptLevel::Pml4, 0, &rules)?;

    Ok(BaseViewCandidate {
        root,
        pages,
        inventory,
        memory_types,
        max_physical_bits,
        execute_only_supported,
    })
}

pub fn build_base_view<A: EptPageAllocator>(
    allocator: A,
    inventory: PhysicalInventory,
    memory_types: NormalizedMemoryMap,
    max_physical_bits: u8,
    page_1g_supported: bool,
    page_2m_supported: bool,
    execute_only_supported: bool,
) -> MonadResult<VerifiedBaseView<A>> {
    let candidate = build_candidate(
        allocator,
        inventory,
        memory_types,
        max_physical_bits,
        page_1g_supported,
        page_2m_supported,
        execute_only_supported,
    )?;
    let ViewVerification { metadata } = verify_view(&candidate)?;
    Ok(VerifiedBaseView {
        candidate,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;

    use super::*;
    use crate::ept::{
        page::fake::{FakePageAllocator, FakePageStats},
        EptMemoryType, MemoryTypeInterval, WalkResult,
    };

    fn inventory(highest_end: u64, configured_limit: u64) -> PhysicalInventory {
        PhysicalInventory::ingest(
            &[PhysicalRange {
                start: 0,
                length: highest_end,
                kind: PhysicalRangeKind::Memory,
            }],
            &[RequiredPhysicalRange {
                start: 0,
                length: highest_end,
            }],
            48,
            Some(configured_limit),
        )
        .expect("inventory")
    }

    fn map(intervals: &[MemoryTypeInterval], aperture: u64) -> NormalizedMemoryMap {
        NormalizedMemoryMap::from_intervals(intervals, aperture).expect("memory map")
    }

    #[test]
    fn aperture_inventory() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let mixed = PhysicalInventory::ingest(
            &[
                PhysicalRange {
                    start: 0,
                    length: 0x8000_0000,
                    kind: PhysicalRangeKind::Memory,
                },
                PhysicalRange {
                    start: 0xf000_0000,
                    length: 0x1000_0000,
                    kind: PhysicalRangeKind::Device,
                },
            ],
            &[RequiredPhysicalRange {
                start: 0xf000_0000,
                length: 0x1000_0000,
            }],
            48,
            None,
        )
        .expect("ram and device inventory");
        assert_eq!(mixed.aperture_end(), 0x1_0000_0000);

        let rounded = inventory(SIZE_1G + PAGE_SIZE_4K, SIZE_1G * 2);
        assert_eq!(rounded.aperture_end(), SIZE_1G * 2);
        let capped = inventory(SIZE_1G + PAGE_SIZE_4K, SIZE_1G + SIZE_2M);
        assert_eq!(capped.aperture_end(), SIZE_1G + SIZE_2M);

        let overflow = PhysicalInventory::ingest(
            &[PhysicalRange {
                start: u64::MAX - PAGE_SIZE_4K + 1,
                length: PAGE_SIZE_4K,
                kind: PhysicalRangeKind::Device,
            }],
            &[],
            48,
            None,
        );
        assert_eq!(
            overflow.map_err(|error| error.code),
            Err(ErrorCode::AddressOverflow)
        );

        let missing = PhysicalInventory::ingest(
            &[PhysicalRange {
                start: 0,
                length: SIZE_2M,
                kind: PhysicalRangeKind::Memory,
            }],
            &[RequiredPhysicalRange {
                start: SIZE_2M,
                length: PAGE_SIZE_4K,
            }],
            48,
            None,
        );
        assert_eq!(
            missing.map_err(|error| error.detail),
            Err(ApertureErrorDetail::MissingRequiredRange as u64)
        );

        let beyond = PhysicalInventory::ingest(
            &[PhysicalRange {
                start: 0,
                length: SIZE_1G + PAGE_SIZE_4K,
                kind: PhysicalRangeKind::Memory,
            }],
            &[],
            48,
            Some(SIZE_1G),
        );
        assert_eq!(
            beyond.map_err(|error| error.detail),
            Err(ApertureErrorDetail::RequiredRangeBeyondLimit as u64)
        );
    }

    #[test]
    fn builder_leaf_choice() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let aperture = SIZE_1G * 2;
        let intervals = [
            MemoryTypeInterval {
                start: 0,
                end_exclusive: SIZE_1G,
                memory_type: EptMemoryType::WriteBack,
            },
            MemoryTypeInterval {
                start: SIZE_1G,
                end_exclusive: SIZE_1G + SIZE_2M,
                memory_type: EptMemoryType::Uncacheable,
            },
            MemoryTypeInterval {
                start: SIZE_1G + SIZE_2M,
                end_exclusive: SIZE_1G + SIZE_2M + PAGE_SIZE_4K,
                memory_type: EptMemoryType::WriteThrough,
            },
            MemoryTypeInterval {
                start: SIZE_1G + SIZE_2M + PAGE_SIZE_4K,
                end_exclusive: aperture,
                memory_type: EptMemoryType::WriteBack,
            },
        ];
        let view = build_base_view(
            FakePageAllocator::new(0x1000_0000_0000, None),
            inventory(SIZE_1G + SIZE_2M + PAGE_SIZE_4K, aperture),
            map(&intervals, aperture),
            48,
            true,
            true,
            false,
        )
        .expect("verified base view");

        let probes = [
            (0, EptLeafSize::Size1G),
            (SIZE_1G, EptLeafSize::Size2M),
            (SIZE_1G + SIZE_2M, EptLeafSize::Size4K),
        ];
        for (gpa, expected) in probes {
            match view.walk(GuestPhysicalAddress::from_page_aligned(gpa).expect("gpa")) {
                WalkResult::Mapping(mapping) => assert_eq!(mapping.leaf_size, expected),
                other => panic!("unexpected walk result: {other:?}"),
            }
        }
        match view.walk(
            GuestPhysicalAddress::from_page_aligned(SIZE_1G + SIZE_2M + PAGE_SIZE_4K).expect("gpa"),
        ) {
            WalkResult::Mapping(mapping) => {
                assert_eq!(mapping.leaf_size, EptLeafSize::Size4K)
            }
            other => panic!("memory boundary was not split: {other:?}"),
        }
        assert!(matches!(
            view.walk(GuestPhysicalAddress::from_page_aligned(aperture).expect("aperture")),
            WalkResult::NotPresent { .. }
        ));

        let two_megabyte = build_base_view(
            FakePageAllocator::new(0x1000_0000_0000, None),
            inventory(SIZE_2M, SIZE_2M),
            map(
                &[MemoryTypeInterval {
                    start: 0,
                    end_exclusive: SIZE_2M,
                    memory_type: EptMemoryType::WriteBack,
                }],
                SIZE_2M,
            ),
            48,
            false,
            true,
            false,
        )
        .expect("2m fallback");
        match two_megabyte.walk(GuestPhysicalAddress::from_page_aligned(0).expect("gpa")) {
            WalkResult::Mapping(mapping) => {
                assert_eq!(mapping.leaf_size, EptLeafSize::Size2M)
            }
            other => panic!("2m fallback was not selected: {other:?}"),
        }

        let four_kib = build_base_view(
            FakePageAllocator::new(0x1000_0000_0000, None),
            inventory(PAGE_SIZE_4K, PAGE_SIZE_4K),
            map(
                &[MemoryTypeInterval {
                    start: 0,
                    end_exclusive: PAGE_SIZE_4K,
                    memory_type: EptMemoryType::WriteBack,
                }],
                PAGE_SIZE_4K,
            ),
            48,
            false,
            false,
            false,
        )
        .expect("4k fallback");
        match four_kib.walk(GuestPhysicalAddress::from_page_aligned(0).expect("gpa")) {
            WalkResult::Mapping(mapping) => {
                assert_eq!(mapping.leaf_size, EptLeafSize::Size4K)
            }
            other => panic!("4k fallback was not selected: {other:?}"),
        }
    }

    #[test]
    fn builder_allocation_failure_each_depth() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        for fail_at in 0..4usize {
            let allocator = FakePageAllocator::new(0x1000_0000_0000, Some(fail_at));
            let stats: Rc<FakePageStats> = Rc::clone(&allocator.stats);
            let result = build_base_view(
                allocator,
                inventory(PAGE_SIZE_4K, PAGE_SIZE_4K),
                map(
                    &[MemoryTypeInterval {
                        start: 0,
                        end_exclusive: PAGE_SIZE_4K,
                        memory_type: EptMemoryType::WriteBack,
                    }],
                    PAGE_SIZE_4K,
                ),
                48,
                false,
                false,
                false,
            );
            assert!(result.is_err(), "allocation {fail_at} must fail");
            assert_eq!(
                stats.allocated.get(),
                stats.freed.get(),
                "allocation {fail_at} leaked a page"
            );
        }
    }
}
