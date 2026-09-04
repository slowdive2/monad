extern crate alloc;

use alloc::vec::Vec;

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{
    backing::BackingPageReference,
    builder::{BaseViewCandidate, PhysicalInventory, VerifiedBaseView},
    entry::{decode_entry, DecodedEptEntry},
    walker::{walk_view, WalkableView},
    EptLeafSize, EptLevel, EptMemoryType, EptPageAllocator, EptPageKind, EptPageOwner,
    EptPageStore, EptPdEntry, EptPdptEntry, EptPermissions, EptPml4Entry, EptPtEntry, GpaRange,
    GuestPhysicalAddress, HostPhysicalAddress, NormalizedMemoryMap, WalkResult, PAGE_SIZE_4K,
};

pub const MAX_PUBLISHED_VIEWS: usize = 8;
pub const MAX_DRAFT_VIEWS: usize = 2;
pub const MAX_BATCH_EDITS: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ViewId {
    pub slot: u16,
    pub reserved: u16,
    pub generation: u64,
}

impl ViewId {
    pub fn validate(self) -> MonadResult<()> {
        if self.reserved != 0 {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::UnsupportedFlags,
                u64::from(self.reserved),
            ));
        }
        validate_generation(self.generation, ErrorPhase::DraftEdit)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DraftId {
    pub slot: u16,
    pub reserved: u16,
    pub generation: u64,
    pub session_nonce: u64,
}

impl DraftId {
    pub fn validate(self, active_session_nonce: u64) -> MonadResult<()> {
        if self.reserved != 0 {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::UnsupportedFlags,
                u64::from(self.reserved),
            ));
        }
        validate_generation(self.generation, ErrorPhase::DraftEdit)?;
        if self.session_nonce != active_session_nonce {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::WrongSession,
                self.session_nonce,
            ));
        }
        Ok(())
    }
}

pub(super) fn validate_generation(generation: u64, phase: ErrorPhase) -> MonadResult<()> {
    if generation == 0 {
        return Err(MonadError::new(phase, ErrorCode::StaleHandle, 0));
    }
    Ok(())
}

pub(super) fn next_generation(current: u64, phase: ErrorPhase) -> MonadResult<u64> {
    current
        .checked_add(1)
        .filter(|value| *value != 0)
        .ok_or_else(|| MonadError::new(phase, ErrorCode::GenerationOverflow, current))
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingMemoryType {
    WriteBack = 6,
    Uncacheable = 0,
}

impl From<BackingMemoryType> for EptMemoryType {
    fn from(value: BackingMemoryType) -> Self {
        match value {
            BackingMemoryType::WriteBack => Self::WriteBack,
            BackingMemoryType::Uncacheable => Self::Uncacheable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftEdit {
    SetPermissions {
        range: GpaRange,
        permissions: EptPermissions,
    },
    MapBacking4K {
        gpa: GuestPhysicalAddress,
        backing: BackingPageReference,
        permissions: EptPermissions,
        memory_type: BackingMemoryType,
    },
    RestoreFromBase {
        range: GpaRange,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingSource {
    Identity,
    Backing(BackingPageReference),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PageOverride {
    gpa: GuestPhysicalAddress,
    hpa: HostPhysicalAddress,
    permissions: EptPermissions,
    memory_type: EptMemoryType,
    backing: Option<BackingPageReference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewMetadata {
    pub source: ViewId,
    pub edit_count: u32,
    pub table_pages: u32,
    pub leaf_1g: u32,
    pub leaf_2m: u32,
    pub leaf_4k: u32,
    pub backing_pages: u32,
    pub readable_pages: u64,
    pub writable_pages: u64,
    pub executable_pages: u64,
}

pub(super) struct ViewImage<A: EptPageAllocator + Clone> {
    root: HostPhysicalAddress,
    pages: EptPageStore<A>,
    inventory: PhysicalInventory,
    memory_types: NormalizedMemoryMap,
    max_physical_bits: u8,
    execute_only_supported: bool,
    owner: EptPageOwner,
    overrides: Vec<PageOverride>,
    source: ViewId,
    edit_count: u32,
}

impl<A: EptPageAllocator + Clone> WalkableView for ViewImage<A> {
    type Allocator = A;

    fn root(&self) -> HostPhysicalAddress {
        self.root
    }

    fn pages(&self) -> &EptPageStore<A> {
        &self.pages
    }

    fn max_physical_bits(&self) -> u8 {
        self.max_physical_bits
    }

    fn execute_only_supported(&self) -> bool {
        self.execute_only_supported
    }

    fn owner(&self) -> EptPageOwner {
        self.owner
    }
}

fn edit_error(code: ErrorCode, detail: u64) -> MonadError {
    MonadError::new(ErrorPhase::DraftEdit, code, detail)
}

fn level_for_kind(kind: EptPageKind) -> EptLevel {
    match kind {
        EptPageKind::Pml4 => EptLevel::Pml4,
        EptPageKind::Pdpt => EptLevel::Pdpt,
        EptPageKind::Pd => EptLevel::Pd,
        EptPageKind::Pt => EptLevel::Pt,
    }
}

fn table_entry(level: EptLevel, hpa: HostPhysicalAddress, bits: u8) -> MonadResult<u64> {
    match level {
        EptLevel::Pml4 => EptPml4Entry::new_table(hpa, bits).map(EptPml4Entry::raw),
        EptLevel::Pdpt => EptPdptEntry::new_table(hpa, bits).map(EptPdptEntry::raw),
        EptLevel::Pd => EptPdEntry::new_table(hpa, bits).map(EptPdEntry::raw),
        EptLevel::Pt => Err(edit_error(ErrorCode::EptVerificationFailure, hpa.get())),
    }
}

fn leaf_entry(
    size: EptLeafSize,
    hpa: HostPhysicalAddress,
    permissions: EptPermissions,
    memory_type: EptMemoryType,
    bits: u8,
) -> MonadResult<u64> {
    match size {
        EptLeafSize::Size1G => {
            EptPdptEntry::new_1g_leaf(hpa, permissions, memory_type, bits).map(EptPdptEntry::raw)
        }
        EptLeafSize::Size2M => {
            EptPdEntry::new_2m_leaf(hpa, permissions, memory_type, bits).map(EptPdEntry::raw)
        }
        EptLeafSize::Size4K => {
            EptPtEntry::new_4k_leaf(hpa, permissions, memory_type, bits).map(EptPtEntry::raw)
        }
    }
}

impl<A: EptPageAllocator + Clone> ViewImage<A> {
    pub(super) fn from_base(base: VerifiedBaseView<A>) -> Self {
        let BaseViewCandidate {
            root,
            mut pages,
            inventory,
            memory_types,
            max_physical_bits,
            execute_only_supported,
        } = base.into_candidate();
        pages.set_owner_all(EptPageOwner::Published);
        Self {
            root,
            pages,
            inventory,
            memory_types,
            max_physical_bits,
            execute_only_supported,
            owner: EptPageOwner::Published,
            overrides: Vec::new(),
            source: ViewId {
                slot: 0,
                reserved: 0,
                generation: 1,
            },
            edit_count: 0,
        }
    }

    pub(super) fn try_clone_as(&self, owner: EptPageOwner) -> MonadResult<Self> {
        let mut pages = EptPageStore::new(self.pages.allocator_clone(), self.max_physical_bits)?;
        let mut remap = Vec::new();
        remap
            .try_reserve_exact(self.pages.len())
            .map_err(|_| edit_error(ErrorCode::AllocationFailure, self.pages.len() as u64))?;
        for index in 0..self.pages.len() {
            let (old_hpa, kind, _, _) = self
                .pages
                .page_at(index)
                .ok_or_else(|| edit_error(ErrorCode::EptVerificationFailure, index as u64))?;
            let new_hpa = pages.allocate(kind, owner)?;
            remap.push((old_hpa, new_hpa));
        }
        for index in (0..self.pages.len()).rev() {
            let (_, kind, _, entries) = self
                .pages
                .page_at(index)
                .ok_or_else(|| edit_error(ErrorCode::EptVerificationFailure, index as u64))?;
            let new_hpa = remap[index].1;
            let level = level_for_kind(kind);
            for (entry_index, raw) in entries.iter().copied().enumerate() {
                let copied = match decode_entry(
                    level,
                    raw,
                    self.max_physical_bits,
                    self.execute_only_supported,
                ) {
                    Ok(DecodedEptEntry::Table { hpa, .. }) => {
                        let child = remap
                            .iter()
                            .find(|(old, _)| *old == hpa)
                            .map(|(_, new)| *new)
                            .ok_or_else(|| {
                                edit_error(ErrorCode::EptVerificationFailure, hpa.get())
                            })?;
                        table_entry(level, child, self.max_physical_bits)?
                    }
                    Ok(_) => raw,
                    Err(error) => {
                        return Err(edit_error(ErrorCode::EptVerificationFailure, error as u64))
                    }
                };
                pages.write_entry(new_hpa, entry_index, copied)?;
            }
        }
        let root = remap
            .iter()
            .find(|(old, _)| *old == self.root)
            .map(|(_, new)| *new)
            .ok_or_else(|| edit_error(ErrorCode::EptVerificationFailure, self.root.get()))?;
        let mut overrides = Vec::new();
        overrides
            .try_reserve_exact(self.overrides.len())
            .map_err(|_| edit_error(ErrorCode::AllocationFailure, self.overrides.len() as u64))?;
        overrides.extend_from_slice(&self.overrides);
        Ok(Self {
            root,
            pages,
            inventory: self.inventory.clone(),
            memory_types: self.memory_types.clone(),
            max_physical_bits: self.max_physical_bits,
            execute_only_supported: self.execute_only_supported,
            owner,
            overrides,
            source: self.source,
            edit_count: self.edit_count,
        })
    }

    fn table_child(
        &self,
        table: HostPhysicalAddress,
        level: EptLevel,
        address: u64,
    ) -> MonadResult<DecodedEptEntry> {
        let shift = match level {
            EptLevel::Pml4 => 39,
            EptLevel::Pdpt => 30,
            EptLevel::Pd => 21,
            EptLevel::Pt => 12,
        };
        let index = ((address >> shift) & 0x1ff) as usize;
        let raw = self.pages.read_entry(table, index)?;
        decode_entry(
            level,
            raw,
            self.max_physical_bits,
            self.execute_only_supported,
        )
        .map_err(|error| edit_error(ErrorCode::EptVerificationFailure, error as u64))
    }

    fn ensure_4k(&mut self, address: u64) -> MonadResult<(HostPhysicalAddress, usize)> {
        let pdpt = match self.table_child(self.root, EptLevel::Pml4, address)? {
            DecodedEptEntry::Table { hpa, .. } => hpa,
            _ => return Err(edit_error(ErrorCode::EptVerificationFailure, address)),
        };
        let pdpt_index = ((address >> 30) & 0x1ff) as usize;
        let pd = match self.table_child(pdpt, EptLevel::Pdpt, address)? {
            DecodedEptEntry::Table { hpa, .. } => hpa,
            DecodedEptEntry::Leaf {
                hpa,
                size: EptLeafSize::Size1G,
                permissions,
                memory_type,
            } => {
                let child = self.pages.allocate(EptPageKind::Pd, self.owner)?;
                for index in 0..512usize {
                    let offset = (index as u64)
                        .checked_mul(EptLeafSize::Size2M.bytes())
                        .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, address))?;
                    let child_hpa = HostPhysicalAddress::for_mapping(
                        hpa.get()
                            .checked_add(offset)
                            .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, hpa.get()))?,
                        EptLeafSize::Size2M.bytes(),
                        EptLeafSize::Size2M.bytes(),
                        self.max_physical_bits,
                    )?;
                    let raw = leaf_entry(
                        EptLeafSize::Size2M,
                        child_hpa,
                        permissions,
                        memory_type,
                        self.max_physical_bits,
                    )?;
                    self.pages.write_entry(child, index, raw)?;
                }
                let raw = EptPdptEntry::new_table(child, self.max_physical_bits)?.raw();
                self.pages.write_entry(pdpt, pdpt_index, raw)?;
                child
            }
            _ => return Err(edit_error(ErrorCode::EptVerificationFailure, address)),
        };
        let pd_index = ((address >> 21) & 0x1ff) as usize;
        let pt = match self.table_child(pd, EptLevel::Pd, address)? {
            DecodedEptEntry::Table { hpa, .. } => hpa,
            DecodedEptEntry::Leaf {
                hpa,
                size: EptLeafSize::Size2M,
                permissions,
                memory_type,
            } => {
                let child = self.pages.allocate(EptPageKind::Pt, self.owner)?;
                for index in 0..512usize {
                    let offset = (index as u64)
                        .checked_mul(PAGE_SIZE_4K)
                        .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, address))?;
                    let child_hpa = HostPhysicalAddress::for_mapping(
                        hpa.get()
                            .checked_add(offset)
                            .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, hpa.get()))?,
                        PAGE_SIZE_4K,
                        PAGE_SIZE_4K,
                        self.max_physical_bits,
                    )?;
                    let raw = leaf_entry(
                        EptLeafSize::Size4K,
                        child_hpa,
                        permissions,
                        memory_type,
                        self.max_physical_bits,
                    )?;
                    self.pages.write_entry(child, index, raw)?;
                }
                let raw = EptPdEntry::new_table(child, self.max_physical_bits)?.raw();
                self.pages.write_entry(pd, pd_index, raw)?;
                child
            }
            _ => return Err(edit_error(ErrorCode::EptVerificationFailure, address)),
        };
        Ok((pt, ((address >> 12) & 0x1ff) as usize))
    }

    fn override_index(&self, gpa: GuestPhysicalAddress) -> Result<usize, usize> {
        self.overrides.binary_search_by_key(&gpa, |entry| entry.gpa)
    }

    fn logical_mapping(&self, gpa: GuestPhysicalAddress) -> MonadResult<PageOverride> {
        if let Ok(index) = self.override_index(gpa) {
            return Ok(self.overrides[index]);
        }
        match walk_view(self, gpa) {
            WalkResult::Mapping(mapping) => Ok(PageOverride {
                gpa,
                hpa: mapping.hpa_page,
                permissions: mapping.permissions,
                memory_type: mapping.memory_type,
                backing: None,
            }),
            WalkResult::NotPresent { .. } => {
                Err(edit_error(ErrorCode::EptVerificationFailure, gpa.get()))
            }
            WalkResult::Invalid(error) => {
                Err(edit_error(ErrorCode::EptVerificationFailure, error.detail))
            }
        }
    }

    fn put_override(&mut self, entry: PageOverride) -> MonadResult<()> {
        match self.override_index(entry.gpa) {
            Ok(index) => self.overrides[index] = entry,
            Err(index) => {
                self.overrides.try_reserve(1).map_err(|_| {
                    edit_error(ErrorCode::AllocationFailure, self.overrides.len() as u64)
                })?;
                self.overrides.insert(index, entry);
            }
        }
        Ok(())
    }

    fn remove_override(&mut self, gpa: GuestPhysicalAddress) {
        if let Ok(index) = self.override_index(gpa) {
            self.overrides.remove(index);
        }
    }

    fn write_4k(&mut self, entry: PageOverride) -> MonadResult<()> {
        let (pt, index) = self.ensure_4k(entry.gpa.get())?;
        let raw = leaf_entry(
            EptLeafSize::Size4K,
            entry.hpa,
            entry.permissions,
            entry.memory_type,
            self.max_physical_bits,
        )?;
        self.pages.write_entry(pt, index, raw)?;
        Ok(())
    }

    pub(super) fn apply_edit<F>(
        &mut self,
        edit: DraftEdit,
        mut resolve_backing: F,
    ) -> MonadResult<()>
    where
        F: FnMut(BackingPageReference) -> MonadResult<HostPhysicalAddress>,
    {
        match edit {
            DraftEdit::SetPermissions { range, permissions } => {
                let end = range.end()?;
                let mut address = range.start().get();
                while address < end {
                    let gpa = GuestPhysicalAddress::from_page_aligned(address)?;
                    let mut mapping = self.logical_mapping(gpa)?;
                    mapping.permissions = permissions;
                    self.write_4k(mapping)?;
                    self.put_override(mapping)?;
                    address = address
                        .checked_add(PAGE_SIZE_4K)
                        .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, address))?;
                }
            }
            DraftEdit::MapBacking4K {
                gpa,
                backing,
                permissions,
                memory_type,
            } => {
                if gpa.get() >= self.inventory.aperture_end() {
                    return Err(edit_error(ErrorCode::InvalidRange, gpa.get()));
                }
                let base_type = self
                    .memory_types
                    .memory_type_at(gpa.get())
                    .ok_or_else(|| edit_error(ErrorCode::InvalidRange, gpa.get()))?;
                if EptMemoryType::from(memory_type) != base_type {
                    return Err(edit_error(
                        ErrorCode::UnsupportedMtrrCombination,
                        base_type as u64,
                    ));
                }
                let mapping = PageOverride {
                    gpa,
                    hpa: resolve_backing(backing)?,
                    permissions,
                    memory_type: base_type,
                    backing: Some(backing),
                };
                self.write_4k(mapping)?;
                self.put_override(mapping)?;
            }
            DraftEdit::RestoreFromBase { range } => {
                let end = range.end()?;
                let mut address = range.start().get();
                while address < end {
                    let gpa = GuestPhysicalAddress::from_page_aligned(address)?;
                    let hpa = HostPhysicalAddress::for_mapping(
                        address,
                        PAGE_SIZE_4K,
                        PAGE_SIZE_4K,
                        self.max_physical_bits,
                    )?;
                    let permissions =
                        EptPermissions::new(true, true, true, self.execute_only_supported)?;
                    let memory_type = self
                        .memory_types
                        .memory_type_at(address)
                        .ok_or_else(|| edit_error(ErrorCode::InvalidRange, address))?;
                    self.write_4k(PageOverride {
                        gpa,
                        hpa,
                        permissions,
                        memory_type,
                        backing: None,
                    })?;
                    self.remove_override(gpa);
                    address = address
                        .checked_add(PAGE_SIZE_4K)
                        .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, address))?;
                }
            }
        }
        self.edit_count = self
            .edit_count
            .checked_add(1)
            .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, u64::from(self.edit_count)))?;
        Ok(())
    }

    pub(super) fn backing_refs(&self) -> MonadResult<Vec<BackingPageReference>> {
        let mut refs = Vec::new();
        refs.try_reserve(self.overrides.len())
            .map_err(|_| edit_error(ErrorCode::AllocationFailure, self.overrides.len() as u64))?;
        for entry in &self.overrides {
            if let Some(reference) = entry.backing {
                refs.push(reference);
            }
        }
        refs.sort_unstable();
        refs.dedup();
        Ok(refs)
    }

    pub(super) fn verify(&self) -> MonadResult<ViewMetadata> {
        let mut table_pages = 0u32;
        let mut leaf_1g = 0u32;
        let mut leaf_2m = 0u32;
        let mut leaf_4k = 0u32;
        for page_index in 0..self.pages.len() {
            let (hpa, kind, owner, entries) = self
                .pages
                .page_at(page_index)
                .ok_or_else(|| edit_error(ErrorCode::EptVerificationFailure, page_index as u64))?;
            if owner != self.owner {
                return Err(edit_error(ErrorCode::EptVerificationFailure, hpa.get()));
            }
            table_pages = table_pages
                .checked_add(1)
                .ok_or_else(|| edit_error(ErrorCode::AddressOverflow, u64::from(table_pages)))?;
            let level = level_for_kind(kind);
            for raw in entries.iter().copied() {
                match decode_entry(
                    level,
                    raw,
                    self.max_physical_bits,
                    self.execute_only_supported,
                ) {
                    Ok(DecodedEptEntry::Table {
                        hpa: child,
                        permissions,
                    }) => {
                        if !permissions.read()
                            || !permissions.write()
                            || !permissions.execute()
                            || self.pages.page(child).is_none()
                        {
                            return Err(edit_error(ErrorCode::EptVerificationFailure, child.get()));
                        }
                    }
                    Ok(DecodedEptEntry::Leaf { size, .. }) => match size {
                        EptLeafSize::Size1G => leaf_1g += 1,
                        EptLeafSize::Size2M => leaf_2m += 1,
                        EptLeafSize::Size4K => leaf_4k += 1,
                    },
                    Ok(DecodedEptEntry::NotPresent) => {}
                    Err(error) => {
                        return Err(edit_error(ErrorCode::EptVerificationFailure, error as u64))
                    }
                }
            }
        }
        for entry in &self.overrides {
            if entry.gpa.get() >= self.inventory.aperture_end()
                || self.memory_types.memory_type_at(entry.gpa.get()) != Some(entry.memory_type)
            {
                return Err(edit_error(
                    ErrorCode::EptVerificationFailure,
                    entry.gpa.get(),
                ));
            }
            match walk_view(self, entry.gpa) {
                WalkResult::Mapping(mapping)
                    if entry.permissions.is_present()
                        && mapping.hpa_page == entry.hpa
                        && mapping.permissions == entry.permissions
                        && mapping.memory_type == entry.memory_type => {}
                WalkResult::NotPresent {
                    level: EptLevel::Pt,
                    ..
                } if !entry.permissions.is_present() => {}
                _ => {
                    return Err(edit_error(
                        ErrorCode::EptVerificationFailure,
                        entry.gpa.get(),
                    ))
                }
            }
        }
        let backing_pages = u32::try_from(self.backing_refs()?.len())
            .map_err(|_| edit_error(ErrorCode::AddressOverflow, self.overrides.len() as u64))?;
        let total_pages = self.inventory.aperture_end() / PAGE_SIZE_4K;
        let mut readable_pages = total_pages;
        let mut writable_pages = total_pages;
        let mut executable_pages = total_pages;
        for entry in &self.overrides {
            readable_pages = readable_pages
                .checked_sub(u64::from(!entry.permissions.read()))
                .ok_or_else(|| edit_error(ErrorCode::EptVerificationFailure, entry.gpa.get()))?;
            writable_pages = writable_pages
                .checked_sub(u64::from(!entry.permissions.write()))
                .ok_or_else(|| edit_error(ErrorCode::EptVerificationFailure, entry.gpa.get()))?;
            executable_pages = executable_pages
                .checked_sub(u64::from(!entry.permissions.execute()))
                .ok_or_else(|| edit_error(ErrorCode::EptVerificationFailure, entry.gpa.get()))?;
        }
        Ok(ViewMetadata {
            source: self.source,
            edit_count: self.edit_count,
            table_pages,
            leaf_1g,
            leaf_2m,
            leaf_4k,
            backing_pages,
            readable_pages,
            writable_pages,
            executable_pages,
        })
    }

    pub(super) fn mark_published(
        mut self,
        source: ViewId,
        mut metadata: ViewMetadata,
    ) -> (Self, ViewMetadata) {
        self.source = source;
        metadata.source = source;
        self.owner = EptPageOwner::Published;
        self.pages.set_owner_all(EptPageOwner::Published);
        (self, metadata)
    }

    pub(super) fn eptp(&self) -> u64 {
        (EptMemoryType::WriteBack as u64) | (3u64 << 3) | ((self.root.get() >> 12) << 12)
    }

    pub(super) fn walk(&self, gpa: GuestPhysicalAddress) -> WalkResult {
        let mut result = walk_view(self, gpa);
        if let WalkResult::Mapping(mapping) = &mut result {
            mapping.source = self
                .override_index(gpa)
                .ok()
                .and_then(|index| self.overrides[index].backing)
                .map_or(MappingSource::Identity, MappingSource::Backing);
        }
        result
    }

    #[cfg(test)]
    pub(super) fn table_hpas(&self) -> Vec<u64> {
        (0..self.pages.len())
            .filter_map(|index| self.pages.page_at(index).map(|page| page.0.get()))
            .collect()
    }

    #[cfg(test)]
    pub(super) fn fingerprint(&self) -> Vec<u64> {
        let mut values = Vec::new();
        values.push(self.root.get());
        values.push(self.owner as u64);
        values.push(u64::from(self.edit_count));
        for index in 0..self.pages.len() {
            if let Some((hpa, kind, owner, entries)) = self.pages.page_at(index) {
                values.push(hpa.get());
                values.push(kind as u64);
                values.push(owner as u64);
                values.extend_from_slice(entries);
            }
        }
        for entry in &self.overrides {
            values.push(entry.gpa.get());
            values.push(entry.hpa.get());
            values.push(u64::from(entry.permissions.read()));
            values.push(u64::from(entry.permissions.write()));
            values.push(u64::from(entry.permissions.execute()));
            values.push(entry.memory_type as u64);
            values.push(entry.backing.map_or(u64::MAX, |value| {
                (u64::from(value.backing_id.slot) << 32) | u64::from(value.page_index)
            }));
        }
        values
    }
}

pub(super) struct DraftView<A: EptPageAllocator + Clone> {
    pub(super) id: DraftId,
    pub(super) source: ViewId,
    pub(super) image: ViewImage<A>,
}

pub struct PublishedView<A: EptPageAllocator + Clone> {
    id: ViewId,
    image: ViewImage<A>,
    metadata: ViewMetadata,
}

impl<A: EptPageAllocator + Clone> PublishedView<A> {
    pub const fn id(&self) -> ViewId {
        self.id
    }

    pub const fn metadata(&self) -> ViewMetadata {
        self.metadata
    }

    pub fn walk(&self, gpa: GuestPhysicalAddress) -> WalkResult {
        self.image.walk(gpa)
    }

    pub fn eptp(&self) -> u64 {
        self.image.eptp()
    }

    pub fn aperture_end(&self) -> u64 {
        self.image.inventory.aperture_end()
    }

    pub(super) fn image(&self) -> &ViewImage<A> {
        &self.image
    }

    pub(super) fn new(id: ViewId, image: ViewImage<A>, metadata: ViewMetadata) -> Self {
        Self {
            id,
            image,
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_and_reserved_validation() {
        assert_eq!(
            ViewId {
                slot: 0,
                reserved: 1,
                generation: 1,
            }
            .validate()
            .expect_err("reserved view field")
            .code,
            ErrorCode::UnsupportedFlags
        );
        assert_eq!(
            ViewId {
                slot: 0,
                reserved: 0,
                generation: 0,
            }
            .validate()
            .expect_err("zero view generation")
            .code,
            ErrorCode::StaleHandle
        );
        assert_eq!(
            DraftId {
                slot: 0,
                reserved: 0,
                generation: 1,
                session_nonce: 7,
            }
            .validate(8)
            .expect_err("wrong session")
            .code,
            ErrorCode::WrongSession
        );
        assert_eq!(
            next_generation(u64::MAX, ErrorPhase::DraftEdit)
                .expect_err("generation overflow")
                .code,
            ErrorCode::GenerationOverflow
        );
    }
}
