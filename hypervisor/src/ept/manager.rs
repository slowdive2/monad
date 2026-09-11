extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::pin::Pin;

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{
    backing::{BackingId, BackingPageReference, BackingRegistry, BackingState},
    view::{
        next_generation, DraftView, PublishedView, ViewImage, MAX_BATCH_EDITS, MAX_DRAFT_VIEWS,
        MAX_PUBLISHED_VIEWS,
    },
    DraftEdit, DraftId, EptPageAllocator, EptPageOwner, GuestPhysicalAddress, VerifiedBaseView,
    ViewId, ViewMetadata, WalkResult,
};

struct DraftSlot<A: EptPageAllocator + Clone> {
    generation: u64,
    retired: bool,
    draft: Option<DraftView<A>>,
}

impl<A: EptPageAllocator + Clone> DraftSlot<A> {
    const fn empty() -> Self {
        Self {
            generation: 0,
            retired: false,
            draft: None,
        }
    }
}

pub struct EptViewManager<A: EptPageAllocator + Clone> {
    published: [Option<Pin<Box<PublishedView<A>>>>; MAX_PUBLISHED_VIEWS],
    drafts: [DraftSlot<A>; MAX_DRAFT_VIEWS],
    backings: BackingRegistry<A>,
    next_publish_slot: u16,
    session_nonce: u64,
    max_physical_bits: u8,
    unrestricted_edits: bool,
    targets: Vec<(super::HostPhysicalAddress, BackingPageReference)>,
}

impl<A: EptPageAllocator + Clone> EptViewManager<A> {
    pub fn new(
        base: VerifiedBaseView<A>,
        allocator: A,
        session_nonce: u64,
        max_physical_bits: u8,
        unrestricted_edits: bool,
    ) -> MonadResult<Self> {
        if session_nonce == 0 {
            return Err(MonadError::new(
                ErrorPhase::Session,
                ErrorCode::WrongSession,
                0,
            ));
        }
        let image = ViewImage::from_base(base, session_nonce);
        let metadata = image.verify()?;
        let base_id = ViewId {
            slot: 0,
            reserved: 0,
            generation: session_nonce,
        };
        let base = Box::pin(PublishedView::new(base_id, image, metadata));
        let mut published = core::array::from_fn(|_| None);
        published[0] = Some(base);
        Ok(Self {
            published,
            drafts: core::array::from_fn(|_| DraftSlot::empty()),
            backings: BackingRegistry::new(allocator)?,
            next_publish_slot: 1,
            session_nonce,
            max_physical_bits,
            unrestricted_edits,
            targets: Vec::new(),
        })
    }

    fn published(&self, id: ViewId) -> MonadResult<&PublishedView<A>> {
        id.validate()?;
        let view = self
            .published
            .get(id.slot as usize)
            .and_then(Option::as_ref)
            .map(|view| view.as_ref().get_ref())
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
            })?;
        if view.id() != id {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::StaleHandle,
                id.generation,
            ));
        }
        Ok(view)
    }

    pub fn published_view(&self, id: ViewId) -> MonadResult<&PublishedView<A>> {
        self.published(id)
    }

    pub fn published_ids(&self, output: &mut [ViewId]) -> usize {
        let mut count = 0usize;
        for view in self.published.iter().flatten() {
            if count == output.len() {
                break;
            }
            output[count] = view.id();
            count += 1;
        }
        count
    }

    pub fn published_count(&self) -> usize {
        self.published.iter().flatten().count()
    }

    pub fn aperture_end(&self) -> MonadResult<u64> {
        self.published
            .iter()
            .flatten()
            .next()
            .map(|view| view.aperture_end())
            .ok_or_else(|| MonadError::new(ErrorPhase::EptBuild, ErrorCode::WrongObjectState, 0))
    }

    fn draft_index(&self, id: DraftId) -> MonadResult<usize> {
        id.validate(self.session_nonce)?;
        let slot = self.drafts.get(id.slot as usize).ok_or_else(|| {
            MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
        })?;
        if slot.generation != id.generation
            || slot.draft.as_ref().is_none_or(|draft| draft.id != id)
        {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::StaleHandle,
                id.generation,
            ));
        }
        Ok(id.slot as usize)
    }

    pub fn create_draft(&mut self, source: ViewId) -> MonadResult<DraftId> {
        let index = self
            .drafts
            .iter()
            .position(|slot| slot.draft.is_none() && !slot.retired)
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::DraftCapacity,
                    MAX_DRAFT_VIEWS as u64,
                )
            })?;
        let generation = match next_generation(self.drafts[index].generation, ErrorPhase::DraftEdit)
        {
            Ok(generation) => generation,
            Err(error) => {
                self.drafts[index].retired = true;
                return Err(error);
            }
        };
        let image = self
            .published(source)?
            .image()
            .try_clone_as(EptPageOwner::Draft)?;
        let refs = image.backing_refs()?;
        self.backings
            .adjust_draft_refs(&refs, self.session_nonce, true)?;
        let id = DraftId {
            slot: index as u16,
            reserved: 0,
            generation,
            session_nonce: self.session_nonce,
        };
        self.drafts[index].generation = generation;
        self.drafts[index].draft = Some(DraftView { id, source, image });
        Ok(id)
    }

    pub fn discard_draft(&mut self, id: DraftId) -> MonadResult<()> {
        let index = self.draft_index(id)?;
        let draft = self.drafts[index].draft.take().ok_or_else(|| {
            MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
        })?;
        let refs = draft.image.backing_refs()?;
        self.backings
            .adjust_draft_refs(&refs, self.session_nonce, false)?;
        Ok(())
    }

    pub fn apply_batch(&mut self, id: DraftId, edits: &[DraftEdit]) -> MonadResult<()> {
        if edits.is_empty() || edits.len() > MAX_BATCH_EDITS {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::InvalidRange,
                edits.len() as u64,
            ));
        }
        let index = self.draft_index(id)?;
        for (index, edit) in edits.iter().enumerate() {
            self.validate_target_edit(*edit)
                .map_err(|error| error.at_operation(index as u32))?;
        }
        let old_refs = self.drafts[index]
            .draft
            .as_ref()
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
            })?
            .image
            .backing_refs()?;
        let mut candidate = self.drafts[index]
            .draft
            .as_ref()
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
            })?
            .image
            .try_clone_as(EptPageOwner::Draft)?;
        for (operation, edit) in edits.iter().copied().enumerate() {
            let result = candidate.apply_edit(edit, |reference| {
                self.backings.page_hpa(reference, self.session_nonce)
            });
            if let Err(error) = result {
                return Err(error.at_operation(operation as u32));
            }
        }
        candidate
            .verify()
            .map_err(|error| error.at_operation(edits.len() as u32))?;
        let new_refs = candidate.backing_refs()?;
        let added = difference(&new_refs, &old_refs)?;
        let removed = difference(&old_refs, &new_refs)?;
        self.backings
            .adjust_draft_refs(&added, self.session_nonce, true)?;
        self.backings
            .adjust_draft_refs(&removed, self.session_nonce, false)?;
        let draft = self.drafts[index].draft.as_mut().ok_or_else(|| {
            MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
        })?;
        draft.image = candidate;
        Ok(())
    }

    pub fn publish_draft(&mut self, id: DraftId) -> MonadResult<ViewId> {
        let index = self.draft_index(id)?;
        let publish_index = self.next_publish_slot as usize;
        if publish_index >= MAX_PUBLISHED_VIEWS {
            return Err(MonadError::new(
                ErrorPhase::Publish,
                ErrorCode::PublishedViewCapacity,
                self.next_publish_slot as u64,
            ));
        }
        let draft = self.drafts[index].draft.as_ref().ok_or_else(|| {
            MonadError::new(ErrorPhase::Publish, ErrorCode::StaleHandle, id.generation)
        })?;
        let metadata = draft.image.verify()?;
        let refs = draft.image.backing_refs()?;
        self.backings
            .adjust_published_refs(&refs, self.session_nonce, true)?;
        self.backings
            .adjust_draft_refs(&refs, self.session_nonce, false)?;
        let draft = self.drafts[index].draft.take().ok_or_else(|| {
            MonadError::new(ErrorPhase::Publish, ErrorCode::StaleHandle, id.generation)
        })?;
        let view_id = ViewId {
            slot: self.next_publish_slot,
            reserved: 0,
            generation: self.session_nonce,
        };
        let (image, metadata) = draft.image.mark_published(draft.source, metadata);
        self.published[publish_index] =
            Some(Box::pin(PublishedView::new(view_id, image, metadata)));
        self.next_publish_slot = self.next_publish_slot.checked_add(1).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::Publish,
                ErrorCode::GenerationOverflow,
                self.next_publish_slot as u64,
            )
        })?;
        Ok(view_id)
    }

    pub fn walk(&self, id: ViewId, gpa: GuestPhysicalAddress) -> MonadResult<WalkResult> {
        Ok(self.published(id)?.walk(gpa))
    }

    pub fn walk_draft(&self, id: DraftId, gpa: GuestPhysicalAddress) -> MonadResult<WalkResult> {
        let index = self.draft_index(id)?;
        self.drafts[index]
            .draft
            .as_ref()
            .map(|draft| draft.image.walk(gpa))
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
            })
    }

    pub fn metadata(&self, id: ViewId) -> MonadResult<ViewMetadata> {
        Ok(self.published(id)?.metadata())
    }

    pub fn base_id(&self) -> ViewId {
        ViewId {
            slot: 0,
            reserved: 0,
            generation: self.session_nonce,
        }
    }

    /// Pin a dedicated allocation page; it cannot become a stack/table/control object.
    pub fn register_target(
        &mut self,
        backing: BackingId,
        page_index: u32,
    ) -> MonadResult<GuestPhysicalAddress> {
        let reference = BackingPageReference {
            backing_id: backing,
            page_index,
        };
        let hpa = self.backings.page_hpa(reference, self.session_nonce)?;
        let gpa = GuestPhysicalAddress::from_page_aligned(hpa.get())?;
        match self.walk(self.base_id(), gpa)? {
            WalkResult::Mapping(mapping)
                if mapping.memory_type == super::EptMemoryType::WriteBack => {}
            _ => {
                return Err(MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::UnsupportedMtrrCombination,
                    hpa.get(),
                ))
            }
        }
        if !self.targets.iter().any(|(physical, _)| *physical == hpa) {
            self.targets.try_reserve(1).map_err(|_| {
                MonadError::new(ErrorPhase::DraftEdit, ErrorCode::AllocationFailure, 1)
            })?;
            self.backings.pin_target(backing, self.session_nonce)?;
            self.targets.push((hpa, reference));
        }
        Ok(gpa)
    }

    fn validate_target_edit(&self, edit: DraftEdit) -> MonadResult<()> {
        if self.unrestricted_edits {
            return Ok(());
        }
        let (start, end) = match edit {
            DraftEdit::SetPermissions { range, .. } | DraftEdit::RestoreFromBase { range } => {
                (range.start().get(), range.end()?)
            }
            DraftEdit::MapBacking4K { gpa, .. } => (
                gpa.get(),
                gpa.get().checked_add(super::PAGE_SIZE_4K).ok_or_else(|| {
                    MonadError::new(ErrorPhase::DraftEdit, ErrorCode::AddressOverflow, gpa.get())
                })?,
            ),
        };
        // Bound validation by the owned page count, even for a malicious huge range.
        let covered = self
            .targets
            .iter()
            .filter(|(hpa, _)| hpa.get() >= start && hpa.get() < end)
            .count() as u64;
        if covered != (end - start) / super::PAGE_SIZE_4K {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::AccessDenied,
                start,
            ));
        }
        Ok(())
    }

    pub fn allocate_backing(&mut self, page_count: u32, immutable: bool) -> MonadResult<BackingId> {
        self.backings.allocate(
            page_count,
            self.session_nonce,
            self.max_physical_bits,
            immutable,
        )
    }

    pub fn write_backing(&mut self, id: BackingId, offset: usize, data: &[u8]) -> MonadResult<()> {
        self.backings.write(id, self.session_nonce, offset, data)
    }

    pub fn free_backing(&mut self, id: BackingId) -> MonadResult<()> {
        self.backings.free(id, self.session_nonce)
    }

    pub fn backing_state(&self, id: BackingId) -> MonadResult<BackingState> {
        self.backings.state(id, self.session_nonce)
    }

    pub fn published_eptp(&self, id: ViewId) -> MonadResult<u64> {
        Ok(self.published(id)?.eptp())
    }

    #[cfg(test)]
    fn draft(&self, id: DraftId) -> MonadResult<&DraftView<A>> {
        self.drafts[self.draft_index(id)?]
            .draft
            .as_ref()
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
            })
    }

    #[cfg(test)]
    fn backing_counts(&self, id: BackingId) -> Option<(u32, u32, BackingState)> {
        self.backings.counts(id)
    }

    #[cfg(test)]
    fn backing_page(&self, id: BackingId, page: u32) -> MonadResult<&[u8; 4096]> {
        self.backings.snapshot_page(id, self.session_nonce, page)
    }
}

fn difference(
    left: &[BackingPageReference],
    right: &[BackingPageReference],
) -> MonadResult<Vec<BackingPageReference>> {
    let mut values = Vec::new();
    values.try_reserve(left.len()).map_err(|_| {
        MonadError::new(
            ErrorPhase::DraftEdit,
            ErrorCode::AllocationFailure,
            left.len() as u64,
        )
    })?;
    for value in left {
        if right.binary_search(value).is_err() {
            values.push(*value);
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;

    use super::*;
    use crate::ept::{
        build_base_view,
        page::fake::{FakePageAllocator, FakePageStats},
        BackingMemoryType, EptLeafSize, EptMemoryType, EptPermissions, GpaRange,
        MemoryTypeInterval, NormalizedMemoryMap, PhysicalInventory, PhysicalRange,
        PhysicalRangeKind,
    };

    const ONE_GIB: u64 = EptLeafSize::Size1G as u64;

    fn manager() -> (
        EptViewManager<FakePageAllocator>,
        FakePageAllocator,
        Rc<FakePageStats>,
    ) {
        let allocator = FakePageAllocator::new(0x1000_0000, None);
        let stats = Rc::clone(&allocator.stats);
        let inventory = PhysicalInventory::ingest(
            &[PhysicalRange {
                start: 0,
                length: ONE_GIB,
                kind: PhysicalRangeKind::Memory,
            }],
            &[],
            48,
            Some(ONE_GIB),
        )
        .expect("inventory");
        let memory = NormalizedMemoryMap::from_intervals(
            &[MemoryTypeInterval {
                start: 0,
                end_exclusive: ONE_GIB,
                memory_type: EptMemoryType::WriteBack,
            }],
            ONE_GIB,
        )
        .expect("memory map");
        let base = build_base_view(allocator.clone(), inventory, memory, 48, true, true, false)
            .expect("base");
        (
            EptViewManager::new(base, allocator.clone(), 0x55aa, 48, true).expect("manager"),
            allocator,
            stats,
        )
    }

    fn base_id() -> ViewId {
        ViewId {
            slot: 0,
            reserved: 0,
            generation: 0x55aa,
        }
    }

    fn all() -> EptPermissions {
        EptPermissions::new(true, true, true, false).expect("rwx")
    }

    fn read() -> EptPermissions {
        EptPermissions::new(true, false, false, false).expect("read")
    }

    #[test]
    fn deep_clone_has_no_table_aliases() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let draft = manager.create_draft(base_id()).expect("draft");
        let base = manager
            .published(base_id())
            .expect("base")
            .image()
            .table_hpas();
        let cloned = manager.draft(draft).expect("draft").image.table_hpas();
        assert!(base.iter().all(|hpa| !cloned.contains(hpa)));
        assert_eq!(base.len(), cloned.len());
    }

    #[test]
    fn clone_mapping_equivalence() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let draft = manager.create_draft(base_id()).expect("draft");
        for address in [0, 0x1000, 0x20_0000, ONE_GIB - 0x1000] {
            let gpa = GuestPhysicalAddress::from_page_aligned(address).expect("gpa");
            assert_eq!(
                manager.published(base_id()).expect("base").walk(gpa),
                manager.draft(draft).expect("draft").image.walk(gpa)
            );
        }
    }

    #[test]
    fn split_1g_to_2m_equivalence() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let draft = manager.create_draft(base_id()).expect("draft");
        manager
            .apply_batch(
                draft,
                &[DraftEdit::SetPermissions {
                    range: GpaRange::new(0, 0x1000, ONE_GIB).expect("range"),
                    permissions: all(),
                }],
            )
            .expect("split");
        for index in 0..512u64 {
            let gpa = GuestPhysicalAddress::from_page_aligned(index * 0x20_0000).expect("gpa");
            let WalkResult::Mapping(mapping) = manager.draft(draft).expect("draft").image.walk(gpa)
            else {
                panic!("mapping")
            };
            assert_eq!(mapping.hpa_page.get(), gpa.get());
            assert_eq!(mapping.memory_type, EptMemoryType::WriteBack);
        }
    }

    #[test]
    fn split_2m_to_4k_equivalence() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let draft = manager.create_draft(base_id()).expect("draft");
        manager
            .apply_batch(
                draft,
                &[DraftEdit::SetPermissions {
                    range: GpaRange::new(0, 0x1000, ONE_GIB).expect("range"),
                    permissions: all(),
                }],
            )
            .expect("split");
        for index in 0..512u64 {
            let gpa = GuestPhysicalAddress::from_page_aligned(index * 0x1000).expect("gpa");
            let WalkResult::Mapping(mapping) = manager.draft(draft).expect("draft").image.walk(gpa)
            else {
                panic!("mapping")
            };
            assert_eq!(mapping.hpa_page.get(), gpa.get());
            assert_eq!(mapping.permissions, all());
        }
    }

    #[test]
    fn edit_range_crosses_leaf_boundaries() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let draft = manager.create_draft(base_id()).expect("draft");
        let backing = manager.allocate_backing(1, false).expect("backing");
        let start = 0x20_0000 - 0x1000;
        manager
            .apply_batch(
                draft,
                &[
                    DraftEdit::SetPermissions {
                        range: GpaRange::new(start, 0x3000, ONE_GIB).expect("range"),
                        permissions: read(),
                    },
                    DraftEdit::MapBacking4K {
                        gpa: GuestPhysicalAddress::from_page_aligned(0x20_0000).expect("gpa"),
                        backing: BackingPageReference {
                            backing_id: backing,
                            page_index: 0,
                        },
                        permissions: read(),
                        memory_type: BackingMemoryType::WriteBack,
                    },
                    DraftEdit::RestoreFromBase {
                        range: GpaRange::new(start, 0x1000, ONE_GIB).expect("range"),
                    },
                ],
            )
            .expect("batch");
        let restored = GuestPhysicalAddress::from_page_aligned(start).expect("gpa");
        let WalkResult::Mapping(mapping) =
            manager.draft(draft).expect("draft").image.walk(restored)
        else {
            panic!("mapping")
        };
        assert_eq!(mapping.permissions, all());
        assert_eq!(manager.backing_counts(backing).expect("counts").0, 1);
    }

    #[test]
    fn batch_failure_is_atomic() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, allocator, _) = manager();
        let draft = manager.create_draft(base_id()).expect("draft");
        let before = manager.draft(draft).expect("draft").image.fingerprint();
        let operation = DraftEdit::MapBacking4K {
            gpa: GuestPhysicalAddress::from_page_aligned(0).expect("gpa"),
            backing: BackingPageReference {
                backing_id: BackingId {
                    slot: 0,
                    generation: 99,
                    session_nonce: 0x55aa,
                },
                page_index: 0,
            },
            permissions: read(),
            memory_type: BackingMemoryType::WriteBack,
        };
        assert_eq!(
            manager
                .apply_batch(draft, &[operation])
                .expect_err("stale")
                .operation_index,
            0
        );
        assert_eq!(
            manager.draft(draft).expect("draft").image.fingerprint(),
            before
        );
        allocator.fail_at(Some(allocator.allocation_ordinal()));
        assert!(manager
            .apply_batch(
                draft,
                &[DraftEdit::SetPermissions {
                    range: GpaRange::new(0, 0x1000, ONE_GIB).expect("range"),
                    permissions: read(),
                }],
            )
            .is_err());
        assert_eq!(
            manager.draft(draft).expect("draft").image.fingerprint(),
            before
        );
    }

    #[test]
    fn stale_wrong_session_and_capacity() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let first = manager.create_draft(base_id()).expect("first");
        let second = manager.create_draft(base_id()).expect("second");
        assert_eq!(
            manager.create_draft(base_id()).expect_err("capacity").code,
            ErrorCode::DraftCapacity
        );
        let mut wrong = first;
        wrong.session_nonce = 7;
        assert_eq!(
            manager.discard_draft(wrong).expect_err("session").code,
            ErrorCode::WrongSession
        );
        manager.discard_draft(first).expect("discard");
        assert_eq!(
            manager.discard_draft(first).expect_err("stale").code,
            ErrorCode::StaleHandle
        );
        manager.discard_draft(second).expect("discard");
    }

    #[test]
    fn backing_lifetime() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let immutable = manager.allocate_backing(1, true).expect("immutable");
        assert_eq!(
            manager.backing_state(immutable).expect("state"),
            BackingState::Immutable
        );
        assert_eq!(
            manager
                .write_backing(immutable, 0, &[1])
                .expect_err("immutable write")
                .code,
            ErrorCode::WrongObjectState
        );
        manager.free_backing(immutable).expect("free immutable");
        let backing = manager.allocate_backing(1, false).expect("backing");
        assert!(manager
            .backing_page(backing, 0)
            .expect("page")
            .iter()
            .all(|byte| *byte == 0));
        assert!(manager.write_backing(backing, 4095, &[1, 2]).is_err());
        manager.write_backing(backing, 0, &[1, 2]).expect("write");
        let draft = manager.create_draft(base_id()).expect("draft");
        manager
            .apply_batch(
                draft,
                &[DraftEdit::MapBacking4K {
                    gpa: GuestPhysicalAddress::from_page_aligned(0).expect("gpa"),
                    backing: BackingPageReference {
                        backing_id: backing,
                        page_index: 0,
                    },
                    permissions: read(),
                    memory_type: BackingMemoryType::WriteBack,
                }],
            )
            .expect("map");
        assert_eq!(
            manager.free_backing(backing).expect_err("referenced").code,
            ErrorCode::BackingStillReferenced
        );
        let published = manager.publish_draft(draft).expect("publish");
        assert_eq!(
            manager.backing_state(backing).expect("state"),
            BackingState::PublishedPinned
        );
        assert_eq!(
            manager
                .write_backing(backing, 0, &[3])
                .expect_err("immutable")
                .code,
            ErrorCode::WrongObjectState
        );
        assert!(matches!(
            manager
                .walk(
                    published,
                    GuestPhysicalAddress::from_page_aligned(0).expect("gpa")
                )
                .expect("walk"),
            WalkResult::Mapping(_)
        ));
    }

    #[test]
    fn published_mutation_impossible() {
        let _no_eptp_write = crate::ept::EptpWriteGuard::new();
        let (mut manager, _, _) = manager();
        let draft = manager.create_draft(base_id()).expect("draft");
        let published = manager.publish_draft(draft).expect("publish");
        assert_eq!(
            manager.metadata(published).expect("metadata").source,
            base_id()
        );
    }
    #[test]
    fn registered_target_ownership_precedes_any_batch_mutation() {
        let (mut manager, _, _) = manager();
        manager.unrestricted_edits = false;
        let target = manager
            .allocate_backing(1, false)
            .expect("target allocation");
        let gpa = manager
            .register_target(target, 0)
            .expect("register owned page");
        assert_eq!(
            manager
                .register_target(target, 0)
                .expect("idempotent registration"),
            gpa
        );
        assert_eq!(
            manager
                .free_backing(target)
                .expect_err("target remains owned")
                .code,
            ErrorCode::BackingStillReferenced
        );
        let draft = manager.create_draft(manager.base_id()).expect("draft");
        let overflowing = DraftEdit::MapBacking4K {
            gpa: GuestPhysicalAddress::from_page_aligned(!0xfffu64).expect("aligned"),
            backing: BackingPageReference {
                backing_id: target,
                page_index: 0,
            },
            permissions: all(),
            memory_type: BackingMemoryType::WriteBack,
        };
        assert_eq!(
            manager
                .apply_batch(draft, &[overflowing])
                .expect_err("overflow")
                .code,
            ErrorCode::AddressOverflow
        );
        let before = manager.walk_draft(draft, gpa).expect("before");
        let edit = DraftEdit::SetPermissions {
            range: super::super::GpaRange::new(gpa.get(), 4096, ONE_GIB).expect("range"),
            permissions: super::super::EptPermissions::new(true, false, false, false)
                .expect("permissions"),
        };
        let unowned = DraftEdit::SetPermissions {
            range: super::super::GpaRange::new(0, 4096, ONE_GIB).expect("range"),
            permissions: all(),
        };
        assert_eq!(
            manager
                .apply_batch(draft, &[edit, unowned])
                .expect_err("unowned footprint")
                .operation_index,
            1
        );
        assert_eq!(
            manager.walk_draft(draft, gpa).expect("atomic failure"),
            before
        );
        manager
            .apply_batch(draft, &[edit])
            .expect("owned intervention");
        assert_ne!(manager.walk_draft(draft, gpa).expect("after"), before);
        manager
            .write_backing(target, 0, &[1])
            .expect("target remains mutable before publication");
    }

    #[test]
    fn handles_from_another_instance_cannot_select_replacement_objects() {
        let (mut old, _, _) = manager();
        let old_base = old.base_id();
        let old_draft = old.create_draft(old_base).expect("old draft");
        let old_backing = old.allocate_backing(1, false).expect("old backing");
        let old_view = old.publish_draft(old_draft).expect("old view");
        let (next, allocator, _) = manager();
        // Same slots/generations, new instance; use the production constructor.
        drop(next);
        let inventory = PhysicalInventory::ingest(
            &[PhysicalRange {
                start: 0,
                length: ONE_GIB,
                kind: PhysicalRangeKind::Memory,
            }],
            &[],
            48,
            Some(ONE_GIB),
        )
        .expect("inventory");
        let memory = NormalizedMemoryMap::from_intervals(
            &[MemoryTypeInterval {
                start: 0,
                end_exclusive: ONE_GIB,
                memory_type: EptMemoryType::WriteBack,
            }],
            ONE_GIB,
        )
        .expect("memory");
        let base = build_base_view(allocator.clone(), inventory, memory, 48, true, true, false)
            .expect("base");
        let mut next =
            EptViewManager::new(base, allocator, 0x55ab, 48, true).expect("next instance");
        let draft = next
            .create_draft(next.base_id())
            .expect("replacement draft");
        let backing = next
            .allocate_backing(1, false)
            .expect("replacement backing");
        let view = next.publish_draft(draft).expect("replacement view");
        assert_eq!(old_backing.slot, backing.slot);
        assert_eq!(old_view.slot, view.slot);
        assert!(next.published_view(old_base).is_err());
        assert!(next.published_view(old_view).is_err());
        assert!(next.discard_draft(old_draft).is_err());
        assert!(next.free_backing(old_backing).is_err());
    }

    #[test]
    fn cached_backing_rejects_uncacheable_or_uncovered_physical_aliases() {
        let (mut manager, _, _) = manager();
        let backing = manager.allocate_backing(1, false).expect("backing");
        let draft = manager.create_draft(manager.base_id()).expect("draft");
        let gpa = GuestPhysicalAddress::from_page_aligned(0x2000).expect("gpa");
        let reference = BackingPageReference {
            backing_id: backing,
            page_index: 0,
        };
        let edit = DraftEdit::MapBacking4K {
            gpa,
            backing: reference,
            permissions: all(),
            memory_type: super::super::BackingMemoryType::Uncacheable,
        };
        assert!(manager.apply_batch(draft, &[edit]).is_err());
        // Exercise the actual candidate's physical-type lookup with an HPA outside
        // its map; syntactically valid WB must not substitute for physical evidence.
        let index = manager.draft_index(draft).expect("draft index");
        let image = &mut manager.drafts[index].draft.as_mut().expect("draft").image;
        let wb = DraftEdit::MapBacking4K {
            gpa,
            backing: reference,
            permissions: all(),
            memory_type: super::super::BackingMemoryType::WriteBack,
        };
        assert!(image
            .apply_edit(wb, |_| super::super::HostPhysicalAddress::for_mapping(
                ONE_GIB, 4096, 4096, 48
            ))
            .is_err());
    }
}
