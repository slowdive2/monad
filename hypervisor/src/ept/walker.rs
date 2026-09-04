extern crate alloc;

use alloc::vec::Vec;

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{
    builder::{BaseViewCandidate, BaseViewMetadata},
    entry::{decode_entry, DecodedEptEntry},
    EptLeafSize, EptLevel, EptMemoryType, EptPageAllocator, EptPageKind, EptPageOwner,
    EptPermissions, GuestPhysicalAddress, HostPhysicalAddress, PAGE_SIZE_4K,
};

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptValidationErrorKind {
    AddressOutsideWidth = 1,
    MissingOwnedTable = 2,
    WrongTableKind = 3,
    WrongTableOwner = 4,
    CycleOrSharedTable = 5,
    InvalidEntry = 6,
    ArithmeticOverflow = 7,
    MappingOutsideAperture = 8,
    MappingGapOrOverlap = 9,
    NonIdentityMapping = 10,
    MemoryTypeMismatch = 11,
    PermissionMismatch = 12,
    UnreachableOwnedTable = 13,
    WalkerMismatch = 14,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptValidationError {
    pub kind: EptValidationErrorKind,
    pub level: EptLevel,
    pub gpa: u64,
    pub detail: u64,
}

impl EptValidationError {
    const fn packed_detail(self) -> u64 {
        (self.kind as u64) | ((self.level as u64) << 8) | ((self.gpa >> 12) << 16)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedMapping {
    pub gpa_page: GuestPhysicalAddress,
    pub hpa_page: HostPhysicalAddress,
    pub leaf_size: EptLeafSize,
    pub permissions: EptPermissions,
    pub memory_type: EptMemoryType,
    pub source: super::MappingSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkResult {
    Mapping(ResolvedMapping),
    NotPresent { level: EptLevel, raw_entry: u64 },
    Invalid(EptValidationError),
}

#[derive(Debug)]
pub(super) struct ViewVerification {
    pub(super) metadata: BaseViewMetadata,
}

pub(super) trait WalkableView {
    type Allocator: EptPageAllocator;

    fn root(&self) -> HostPhysicalAddress;
    fn pages(&self) -> &super::EptPageStore<Self::Allocator>;
    fn max_physical_bits(&self) -> u8;
    fn execute_only_supported(&self) -> bool;
    fn owner(&self) -> EptPageOwner;
}

impl<A: EptPageAllocator> WalkableView for BaseViewCandidate<A> {
    type Allocator = A;

    fn root(&self) -> HostPhysicalAddress {
        self.root
    }

    fn pages(&self) -> &super::EptPageStore<Self::Allocator> {
        &self.pages
    }

    fn max_physical_bits(&self) -> u8 {
        self.max_physical_bits
    }

    fn execute_only_supported(&self) -> bool {
        self.execute_only_supported
    }

    fn owner(&self) -> EptPageOwner {
        EptPageOwner::BaseBuild
    }
}

#[derive(Debug, Clone, Copy)]
struct LeafRecord {
    start: u64,
    end_exclusive: u64,
    hpa: HostPhysicalAddress,
    size: EptLeafSize,
    permissions: EptPermissions,
    memory_type: EptMemoryType,
}

fn invalid(
    kind: EptValidationErrorKind,
    level: EptLevel,
    gpa: u64,
    detail: u64,
) -> EptValidationError {
    EptValidationError {
        kind,
        level,
        gpa,
        detail,
    }
}

fn expected_kind(level: EptLevel) -> EptPageKind {
    match level {
        EptLevel::Pml4 => EptPageKind::Pml4,
        EptLevel::Pdpt => EptPageKind::Pdpt,
        EptLevel::Pd => EptPageKind::Pd,
        EptLevel::Pt => EptPageKind::Pt,
    }
}

fn next_level(level: EptLevel) -> Option<EptLevel> {
    match level {
        EptLevel::Pml4 => Some(EptLevel::Pdpt),
        EptLevel::Pdpt => Some(EptLevel::Pd),
        EptLevel::Pd => Some(EptLevel::Pt),
        EptLevel::Pt => None,
    }
}

fn level_shift(level: EptLevel) -> u32 {
    match level {
        EptLevel::Pml4 => 39,
        EptLevel::Pdpt => 30,
        EptLevel::Pd => 21,
        EptLevel::Pt => 12,
    }
}

fn level_span(level: EptLevel) -> u64 {
    1u64 << level_shift(level)
}

pub(super) fn walk<A: EptPageAllocator>(
    view: &BaseViewCandidate<A>,
    gpa: GuestPhysicalAddress,
) -> WalkResult {
    walk_view(view, gpa)
}

pub(super) fn walk_view<V: WalkableView>(view: &V, gpa: GuestPhysicalAddress) -> WalkResult {
    let address = gpa.get();
    if address >= (1u64 << view.max_physical_bits()) {
        return WalkResult::Invalid(invalid(
            EptValidationErrorKind::AddressOutsideWidth,
            EptLevel::Pml4,
            address,
            view.max_physical_bits() as u64,
        ));
    }

    let mut table = view.root();
    let mut visited = [u64::MAX; 4];
    let mut level = EptLevel::Pml4;
    let mut effective_read = true;
    let mut effective_write = true;
    let mut effective_execute = true;
    for depth in 0..4usize {
        if visited[..depth].contains(&table.get()) {
            return WalkResult::Invalid(invalid(
                EptValidationErrorKind::CycleOrSharedTable,
                level,
                address,
                table.get(),
            ));
        }
        visited[depth] = table.get();
        let Some((kind, owner, entries)) = view.pages().page(table) else {
            return WalkResult::Invalid(invalid(
                EptValidationErrorKind::MissingOwnedTable,
                level,
                address,
                table.get(),
            ));
        };
        if kind != expected_kind(level) {
            return WalkResult::Invalid(invalid(
                EptValidationErrorKind::WrongTableKind,
                level,
                address,
                kind as u64,
            ));
        }
        if owner != view.owner() {
            return WalkResult::Invalid(invalid(
                EptValidationErrorKind::WrongTableOwner,
                level,
                address,
                owner as u64,
            ));
        }
        let index = ((address >> level_shift(level)) & 0x1ff) as usize;
        let raw = entries[index];
        match decode_entry(
            level,
            raw,
            view.max_physical_bits(),
            view.execute_only_supported(),
        ) {
            Ok(DecodedEptEntry::NotPresent) => {
                return WalkResult::NotPresent {
                    level,
                    raw_entry: raw,
                }
            }
            Ok(DecodedEptEntry::Table { hpa, permissions }) => {
                let Some(child_level) = next_level(level) else {
                    return WalkResult::Invalid(invalid(
                        EptValidationErrorKind::InvalidEntry,
                        level,
                        address,
                        raw,
                    ));
                };
                effective_read &= permissions.read();
                effective_write &= permissions.write();
                effective_execute &= permissions.execute();
                table = hpa;
                level = child_level;
            }
            Ok(DecodedEptEntry::Leaf {
                hpa,
                size,
                permissions,
                memory_type,
            }) => {
                effective_read &= permissions.read();
                effective_write &= permissions.write();
                effective_execute &= permissions.execute();
                let Ok(effective_permissions) = EptPermissions::new(
                    effective_read,
                    effective_write,
                    effective_execute,
                    view.execute_only_supported(),
                ) else {
                    return WalkResult::Invalid(invalid(
                        EptValidationErrorKind::PermissionMismatch,
                        level,
                        address,
                        0,
                    ));
                };
                let offset = address & (size.bytes() - 1);
                let Some(resolved_hpa) = hpa.get().checked_add(offset) else {
                    return WalkResult::Invalid(invalid(
                        EptValidationErrorKind::ArithmeticOverflow,
                        level,
                        address,
                        hpa.get(),
                    ));
                };
                let Ok(hpa_page) = HostPhysicalAddress::for_mapping(
                    resolved_hpa,
                    PAGE_SIZE_4K,
                    PAGE_SIZE_4K,
                    view.max_physical_bits(),
                ) else {
                    return WalkResult::Invalid(invalid(
                        EptValidationErrorKind::AddressOutsideWidth,
                        level,
                        address,
                        resolved_hpa,
                    ));
                };
                return WalkResult::Mapping(ResolvedMapping {
                    gpa_page: gpa,
                    hpa_page,
                    leaf_size: size,
                    permissions: effective_permissions,
                    memory_type,
                    source: super::MappingSource::Identity,
                });
            }
            Err(error) => {
                return WalkResult::Invalid(invalid(
                    EptValidationErrorKind::InvalidEntry,
                    level,
                    address,
                    error as u64,
                ))
            }
        }
    }
    WalkResult::Invalid(invalid(
        EptValidationErrorKind::InvalidEntry,
        level,
        address,
        0,
    ))
}

fn scan_table<A: EptPageAllocator>(
    view: &BaseViewCandidate<A>,
    hpa: HostPhysicalAddress,
    level: EptLevel,
    table_base: u64,
    visited: &mut Vec<u64>,
    leaves: &mut Vec<LeafRecord>,
) -> Result<(), EptValidationError> {
    if visited.contains(&hpa.get()) {
        return Err(invalid(
            EptValidationErrorKind::CycleOrSharedTable,
            level,
            table_base,
            hpa.get(),
        ));
    }
    visited.try_reserve(1).map_err(|_| {
        invalid(
            EptValidationErrorKind::ArithmeticOverflow,
            level,
            table_base,
            0,
        )
    })?;
    visited.push(hpa.get());

    let Some((kind, owner, entries)) = view.pages.page(hpa) else {
        return Err(invalid(
            EptValidationErrorKind::MissingOwnedTable,
            level,
            table_base,
            hpa.get(),
        ));
    };
    if kind != expected_kind(level) {
        return Err(invalid(
            EptValidationErrorKind::WrongTableKind,
            level,
            table_base,
            kind as u64,
        ));
    }
    if owner != EptPageOwner::BaseBuild {
        return Err(invalid(
            EptValidationErrorKind::WrongTableOwner,
            level,
            table_base,
            owner as u64,
        ));
    }
    let span = level_span(level);
    for (index, raw) in entries.iter().copied().enumerate() {
        let entry_base = table_base.checked_add(index as u64 * span).ok_or_else(|| {
            invalid(
                EptValidationErrorKind::ArithmeticOverflow,
                level,
                table_base,
                index as u64,
            )
        })?;
        match decode_entry(
            level,
            raw,
            view.max_physical_bits,
            view.execute_only_supported,
        ) {
            Ok(DecodedEptEntry::NotPresent) => {}
            Ok(DecodedEptEntry::Table {
                hpa: child,
                permissions,
            }) => {
                let Some(child_level) = next_level(level) else {
                    return Err(invalid(
                        EptValidationErrorKind::InvalidEntry,
                        level,
                        entry_base,
                        raw,
                    ));
                };
                if !permissions.read() || !permissions.write() || !permissions.execute() {
                    return Err(invalid(
                        EptValidationErrorKind::PermissionMismatch,
                        level,
                        entry_base,
                        raw,
                    ));
                }
                scan_table(view, child, child_level, entry_base, visited, leaves)?;
            }
            Ok(DecodedEptEntry::Leaf {
                hpa,
                size,
                permissions,
                memory_type,
            }) => {
                let end_exclusive = entry_base.checked_add(size.bytes()).ok_or_else(|| {
                    invalid(
                        EptValidationErrorKind::ArithmeticOverflow,
                        level,
                        entry_base,
                        size.bytes(),
                    )
                })?;
                if entry_base >= view.inventory.aperture_end()
                    || end_exclusive > view.inventory.aperture_end()
                {
                    return Err(invalid(
                        EptValidationErrorKind::MappingOutsideAperture,
                        level,
                        entry_base,
                        end_exclusive,
                    ));
                }
                if hpa.get() != entry_base {
                    return Err(invalid(
                        EptValidationErrorKind::NonIdentityMapping,
                        level,
                        entry_base,
                        hpa.get(),
                    ));
                }
                if !permissions.read() || !permissions.write() || !permissions.execute() {
                    return Err(invalid(
                        EptValidationErrorKind::PermissionMismatch,
                        level,
                        entry_base,
                        raw,
                    ));
                }
                if view.memory_types.uniform_type(entry_base, end_exclusive) != Some(memory_type) {
                    return Err(invalid(
                        EptValidationErrorKind::MemoryTypeMismatch,
                        level,
                        entry_base,
                        memory_type as u64,
                    ));
                }
                leaves.try_reserve(1).map_err(|_| {
                    invalid(
                        EptValidationErrorKind::ArithmeticOverflow,
                        level,
                        entry_base,
                        0,
                    )
                })?;
                leaves.push(LeafRecord {
                    start: entry_base,
                    end_exclusive,
                    hpa,
                    size,
                    permissions,
                    memory_type,
                });
            }
            Err(error) => {
                return Err(invalid(
                    EptValidationErrorKind::InvalidEntry,
                    level,
                    entry_base,
                    error as u64,
                ))
            }
        }
    }
    Ok(())
}

fn verify_probe<A: EptPageAllocator>(
    view: &BaseViewCandidate<A>,
    address: u64,
) -> Result<(), EptValidationError> {
    let gpa = GuestPhysicalAddress::from_page_aligned(address).map_err(|error| {
        invalid(
            EptValidationErrorKind::WalkerMismatch,
            EptLevel::Pt,
            address,
            error.detail,
        )
    })?;
    match walk(view, gpa) {
        WalkResult::Mapping(mapping)
            if mapping.hpa_page.get() == address
                && mapping.gpa_page == gpa
                && mapping.permissions.read()
                && mapping.permissions.write()
                && mapping.permissions.execute()
                && view.memory_types.memory_type_at(address) == Some(mapping.memory_type) =>
        {
            Ok(())
        }
        WalkResult::Invalid(error) => Err(error),
        _ => Err(invalid(
            EptValidationErrorKind::WalkerMismatch,
            EptLevel::Pt,
            address,
            0,
        )),
    }
}

pub(super) fn verify_view<A: EptPageAllocator>(
    view: &BaseViewCandidate<A>,
) -> MonadResult<ViewVerification> {
    let mut visited = Vec::new();
    let mut leaves = Vec::new();
    if let Err(error) = scan_table(
        view,
        view.root,
        EptLevel::Pml4,
        0,
        &mut visited,
        &mut leaves,
    ) {
        return Err(MonadError::new(
            ErrorPhase::EptBuild,
            ErrorCode::EptVerificationFailure,
            error.packed_detail(),
        ));
    }
    leaves.sort_unstable_by_key(|leaf| leaf.start);
    let mut cursor = 0u64;
    for leaf in &leaves {
        if leaf.start != cursor {
            let error = invalid(
                EptValidationErrorKind::MappingGapOrOverlap,
                EptLevel::Pt,
                cursor,
                leaf.start,
            );
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptVerificationFailure,
                error.packed_detail(),
            ));
        }
        cursor = leaf.end_exclusive;
    }
    if cursor != view.inventory.aperture_end() || visited.len() != view.pages.len() {
        let kind = if cursor != view.inventory.aperture_end() {
            EptValidationErrorKind::MappingGapOrOverlap
        } else {
            EptValidationErrorKind::UnreachableOwnedTable
        };
        let error = invalid(kind, EptLevel::Pml4, cursor, view.pages.len() as u64);
        return Err(MonadError::new(
            ErrorPhase::EptBuild,
            ErrorCode::EptVerificationFailure,
            error.packed_detail(),
        ));
    }

    let mut probes = Vec::new();
    let leaf_probe_capacity = leaves.len().checked_mul(4).ok_or_else(|| {
        MonadError::new(
            ErrorPhase::EptBuild,
            ErrorCode::AddressOverflow,
            leaves.len() as u64,
        )
    })?;
    let interval_probe_capacity = view
        .memory_types
        .intervals()
        .len()
        .checked_mul(4)
        .ok_or_else(|| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::AddressOverflow,
                view.memory_types.intervals().len() as u64,
            )
        })?;
    let probe_capacity = leaf_probe_capacity
        .checked_add(interval_probe_capacity)
        .ok_or_else(|| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::AddressOverflow,
                leaves.len() as u64,
            )
        })?;
    probes.try_reserve(probe_capacity).map_err(|_| {
        MonadError::new(
            ErrorPhase::EptBuild,
            ErrorCode::AllocationFailure,
            probe_capacity as u64,
        )
    })?;
    for leaf in &leaves {
        probes.push(leaf.start);
        probes.push(leaf.end_exclusive - PAGE_SIZE_4K);
        if leaf.start >= PAGE_SIZE_4K {
            probes.push(leaf.start - PAGE_SIZE_4K);
        }
        if leaf.end_exclusive < view.inventory.aperture_end() {
            probes.push(leaf.end_exclusive);
        }
    }
    for interval in view.memory_types.intervals() {
        probes.push(interval.start);
        probes.push(interval.end_exclusive - PAGE_SIZE_4K);
        if interval.start >= PAGE_SIZE_4K {
            probes.push(interval.start - PAGE_SIZE_4K);
        }
        if interval.end_exclusive < view.inventory.aperture_end() {
            probes.push(interval.end_exclusive);
        }
    }
    probes.sort_unstable();
    probes.dedup();
    for probe in probes {
        if let Err(error) = verify_probe(view, probe) {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptVerificationFailure,
                error.packed_detail(),
            ));
        }
    }

    let mut metadata = BaseViewMetadata {
        table_pages: u32::try_from(visited.len()).map_err(|_| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::AddressOverflow,
                visited.len() as u64,
            )
        })?,
        leaf_1g: 0,
        leaf_2m: 0,
        leaf_4k: 0,
        mapped_pages_4k: 0,
    };
    for leaf in leaves {
        let counter = match leaf.size {
            EptLeafSize::Size1G => &mut metadata.leaf_1g,
            EptLeafSize::Size2M => &mut metadata.leaf_2m,
            EptLeafSize::Size4K => &mut metadata.leaf_4k,
        };
        *counter = counter.checked_add(1).ok_or_else(|| {
            MonadError::new(ErrorPhase::EptBuild, ErrorCode::AddressOverflow, leaf.start)
        })?;
        metadata.mapped_pages_4k = metadata
            .mapped_pages_4k
            .checked_add(leaf.size.bytes() / PAGE_SIZE_4K)
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::EptBuild,
                    ErrorCode::AddressOverflow,
                    leaf.end_exclusive,
                )
            })?;
        if leaf.hpa.get() != leaf.start
            || !leaf.permissions.is_present()
            || view.memory_types.memory_type_at(leaf.start) != Some(leaf.memory_type)
        {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptVerificationFailure,
                leaf.start,
            ));
        }
    }
    Ok(ViewVerification { metadata })
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;

    use super::*;
    use crate::ept::{
        builder::{PhysicalInventory, PhysicalRange, PhysicalRangeKind, RequiredPhysicalRange},
        page::fake::{FakePageAllocator, FakePageStats},
        EptEntryError, MemoryTypeInterval, NormalizedMemoryMap,
    };

    fn candidate() -> (BaseViewCandidate<FakePageAllocator>, Rc<FakePageStats>) {
        let allocator = FakePageAllocator::new(0x1000_0000_0000, None);
        let stats = Rc::clone(&allocator.stats);
        let inventory = PhysicalInventory::ingest(
            &[PhysicalRange {
                start: 0,
                length: PAGE_SIZE_4K,
                kind: PhysicalRangeKind::Memory,
            }],
            &[RequiredPhysicalRange {
                start: 0,
                length: PAGE_SIZE_4K,
            }],
            48,
            Some(PAGE_SIZE_4K),
        )
        .expect("inventory");
        let map = NormalizedMemoryMap::from_intervals(
            &[MemoryTypeInterval {
                start: 0,
                end_exclusive: PAGE_SIZE_4K,
                memory_type: EptMemoryType::WriteBack,
            }],
            PAGE_SIZE_4K,
        )
        .expect("memory map");
        (
            super::super::builder::build_candidate(
                allocator, inventory, map, 48, false, false, false,
            )
            .expect("candidate"),
            stats,
        )
    }

    fn child(raw: u64) -> HostPhysicalAddress {
        HostPhysicalAddress::from_validated(raw & 0x000f_ffff_ffff_f000)
    }

    fn corrupt_root(raw: u64) -> EptValidationErrorKind {
        let (mut view, _) = candidate();
        view.pages
            .write_entry(view.root, 0, raw)
            .expect("write corruption");
        match walk(
            &view,
            GuestPhysicalAddress::from_page_aligned(0).expect("gpa"),
        ) {
            WalkResult::Invalid(error) => error.kind,
            result => panic!("corruption was accepted: {result:?}"),
        }
    }

    fn verification_kind(view: &BaseViewCandidate<FakePageAllocator>) -> EptValidationErrorKind {
        let error = verify_view(view).expect_err("corrupt view must fail");
        match error.detail & 0xff {
            value if value == EptValidationErrorKind::MappingGapOrOverlap as u64 => {
                EptValidationErrorKind::MappingGapOrOverlap
            }
            value if value == EptValidationErrorKind::NonIdentityMapping as u64 => {
                EptValidationErrorKind::NonIdentityMapping
            }
            value if value == EptValidationErrorKind::MemoryTypeMismatch as u64 => {
                EptValidationErrorKind::MemoryTypeMismatch
            }
            value if value == EptValidationErrorKind::PermissionMismatch as u64 => {
                EptValidationErrorKind::PermissionMismatch
            }
            value if value == EptValidationErrorKind::UnreachableOwnedTable as u64 => {
                EptValidationErrorKind::UnreachableOwnedTable
            }
            value => panic!("unexpected verification error {value}"),
        }
    }

    #[test]
    fn walker_rejects_corruption() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (view, _) = candidate();
        let root_raw = view.pages.read_entry(view.root, 0).expect("root entry");
        assert_eq!(
            corrupt_root(root_raw | (1 << 8)),
            EptValidationErrorKind::InvalidEntry
        );
        assert_eq!(
            corrupt_root(root_raw | (1 << 7)),
            EptValidationErrorKind::InvalidEntry
        );
        assert_eq!(
            corrupt_root((root_raw & !1) | 2),
            EptValidationErrorKind::InvalidEntry
        );
        assert_eq!(
            corrupt_root((0x2000_0000_0000u64) | 0x7),
            EptValidationErrorKind::MissingOwnedTable
        );
        assert_eq!(
            corrupt_root(view.root.get() | 0x7),
            EptValidationErrorKind::CycleOrSharedTable
        );

        let (mut view, _) = candidate();
        let root_raw = view.pages.read_entry(view.root, 0).expect("root entry");
        view.pages
            .write_entry(view.root, 0, (root_raw & !0x7) | 1)
            .expect("restrict table permissions");
        match walk(
            &view,
            GuestPhysicalAddress::from_page_aligned(0).expect("gpa"),
        ) {
            WalkResult::Mapping(mapping) => {
                assert!(mapping.permissions.read());
                assert!(!mapping.permissions.write());
                assert!(!mapping.permissions.execute());
            }
            result => panic!("restricted table was not walked: {result:?}"),
        }
        assert_eq!(
            verification_kind(&view),
            EptValidationErrorKind::PermissionMismatch
        );

        for (raw, expected) in [
            (0, EptValidationErrorKind::MappingGapOrOverlap),
            (
                0x1000 | 0x7 | ((EptMemoryType::WriteBack as u64) << 3),
                EptValidationErrorKind::NonIdentityMapping,
            ),
            (
                0x7 | ((EptMemoryType::WriteThrough as u64) << 3),
                EptValidationErrorKind::MemoryTypeMismatch,
            ),
        ] {
            let (mut view, stats) = candidate();
            let pdpt = child(view.pages.read_entry(view.root, 0).expect("pml4e"));
            let pd = child(view.pages.read_entry(pdpt, 0).expect("pdpte"));
            let pt = child(view.pages.read_entry(pd, 0).expect("pde"));
            view.pages.write_entry(pt, 0, raw).expect("corrupt leaf");
            assert_eq!(verification_kind(&view), expected);
            drop(view);
            assert_eq!(stats.allocated.get(), stats.freed.get());
        }

        let (mut view, _) = candidate();
        let pdpt = child(view.pages.read_entry(view.root, 0).expect("pml4e"));
        let pd = child(view.pages.read_entry(pdpt, 0).expect("pdpte"));
        let pt = child(view.pages.read_entry(pd, 0).expect("pde"));
        view.pages
            .write_entry(pt, 0, 0x7 | (2 << 3))
            .expect("invalid memory type");
        match walk(
            &view,
            GuestPhysicalAddress::from_page_aligned(0).expect("gpa"),
        ) {
            WalkResult::Invalid(error) => {
                assert_eq!(error.kind, EptValidationErrorKind::InvalidEntry);
                assert_eq!(error.detail, EptEntryError::InvalidMemoryType as u64);
            }
            result => panic!("invalid memory type was accepted: {result:?}"),
        }

        let (mut view, stats) = candidate();
        let pdpt = child(view.pages.read_entry(view.root, 0).expect("pml4e"));
        let pd = child(view.pages.read_entry(pdpt, 0).expect("pdpte"));
        view.pages
            .write_entry(pd, 0, 0x1000 | 0x80 | 0x7 | (6 << 3))
            .expect("misaligned 2m leaf");
        match walk(
            &view,
            GuestPhysicalAddress::from_page_aligned(0).expect("gpa"),
        ) {
            WalkResult::Invalid(error) => {
                assert_eq!(error.kind, EptValidationErrorKind::InvalidEntry);
                assert_eq!(error.detail, EptEntryError::MisalignedAddress as u64);
            }
            result => panic!("misaligned leaf was accepted: {result:?}"),
        }
        drop(view);
        assert_eq!(stats.allocated.get(), stats.freed.get());

        let (mut view, stats) = candidate();
        view.pages
            .allocate(EptPageKind::Pt, EptPageOwner::BaseBuild)
            .expect("unreachable page");
        assert_eq!(
            verification_kind(&view),
            EptValidationErrorKind::UnreachableOwnedTable
        );
        drop(view);
        assert_eq!(stats.allocated.get(), stats.freed.get());
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn builder_matches_4k_oracle() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        for seed in 0x4d33_0000u64..0x4d33_0020 {
            let mut random = seed;
            let pages = next_random(&mut random) % 2048 + 1;
            let aperture = pages * PAGE_SIZE_4K;
            let mut intervals = Vec::new();
            let mut page = 0u64;
            let mut previous = EptMemoryType::WriteBack;
            while page < pages {
                let run = (next_random(&mut random) % 64 + 1).min(pages - page);
                let mut memory_type = match next_random(&mut random) % 4 {
                    0 => EptMemoryType::WriteBack,
                    1 => EptMemoryType::WriteThrough,
                    2 => EptMemoryType::Uncacheable,
                    _ => EptMemoryType::WriteCombining,
                };
                if memory_type == previous {
                    memory_type = EptMemoryType::WriteProtected;
                }
                intervals.push(MemoryTypeInterval {
                    start: page * PAGE_SIZE_4K,
                    end_exclusive: (page + run) * PAGE_SIZE_4K,
                    memory_type,
                });
                previous = memory_type;
                page += run;
            }
            let allocator = FakePageAllocator::new(0x1000_0000_0000, None);
            let stats = Rc::clone(&allocator.stats);
            let inventory = PhysicalInventory::ingest(
                &[PhysicalRange {
                    start: 0,
                    length: aperture,
                    kind: PhysicalRangeKind::Memory,
                }],
                &[],
                48,
                Some(aperture),
            )
            .expect("inventory");
            let map = NormalizedMemoryMap::from_intervals(&intervals, aperture)
                .expect("normalized oracle");
            let view = super::super::builder::build_base_view(
                allocator, inventory, map, 48, true, true, false,
            )
            .expect("verified view");
            for page in 0..pages {
                let address = page * PAGE_SIZE_4K;
                let expected = intervals
                    .iter()
                    .find(|interval| interval.start <= address && address < interval.end_exclusive)
                    .map(|interval| interval.memory_type)
                    .expect("oracle interval");
                match view
                    .walk(GuestPhysicalAddress::from_page_aligned(address).expect("page address"))
                {
                    WalkResult::Mapping(mapping) => {
                        assert_eq!(mapping.hpa_page.get(), address, "seed {seed:#x}");
                        assert_eq!(mapping.memory_type, expected, "seed {seed:#x}");
                    }
                    result => panic!("seed {seed:#x}, page {page}: {result:?}"),
                }
            }
            drop(view);
            assert_eq!(
                stats.allocated.get(),
                stats.freed.get(),
                "seed {seed:#x} leaked pages"
            );
        }
    }
}
