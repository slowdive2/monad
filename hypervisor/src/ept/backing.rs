extern crate alloc;

use alloc::vec::Vec;

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{view::next_generation, EptPageAllocator, HostPhysicalAddress, PAGE_SIZE_4K};

pub const MAX_BACKING_PAGES: usize = 4096;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BackingId {
    pub slot: u32,
    pub generation: u64,
    pub session_nonce: u64,
}

impl BackingId {
    pub fn validate(self, active_session_nonce: u64) -> MonadResult<()> {
        super::view::validate_generation(self.generation, ErrorPhase::DraftEdit)?;
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BackingPageReference {
    pub backing_id: BackingId,
    pub page_index: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingState {
    Mutable = 1,
    Immutable = 2,
    PublishedPinned = 3,
}

struct BackingPage<T> {
    allocation: T,
    hpa: HostPhysicalAddress,
}

struct BackingObject<A: EptPageAllocator> {
    id: BackingId,
    pages: Vec<BackingPage<A::Allocation>>,
    state: BackingState,
    draft_refs: u32,
    published_refs: u32,
    target_pinned: bool,
}

struct BackingSlot<A: EptPageAllocator> {
    generation: u64,
    retired: bool,
    object: Option<BackingObject<A>>,
}

impl<A: EptPageAllocator> BackingSlot<A> {
    const fn empty() -> Self {
        Self {
            generation: 0,
            retired: false,
            object: None,
        }
    }
}

pub(super) struct BackingRegistry<A: EptPageAllocator + Clone> {
    allocator: A,
    slots: Vec<BackingSlot<A>>,
    live_pages: usize,
}

impl<A: EptPageAllocator + Clone> BackingRegistry<A> {
    pub(super) fn new(allocator: A) -> MonadResult<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(MAX_BACKING_PAGES).map_err(|_| {
            MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::AllocationFailure,
                MAX_BACKING_PAGES as u64,
            )
        })?;
        for _ in 0..MAX_BACKING_PAGES {
            slots.push(BackingSlot::empty());
        }
        Ok(Self {
            allocator,
            slots,
            live_pages: 0,
        })
    }

    fn slot(&self, id: BackingId, nonce: u64) -> MonadResult<&BackingSlot<A>> {
        id.validate(nonce)?;
        let slot = self.slots.get(id.slot as usize).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::StaleHandle,
                u64::from(id.slot),
            )
        })?;
        if slot.generation != id.generation || slot.object.is_none() {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::StaleHandle,
                id.generation,
            ));
        }
        Ok(slot)
    }

    fn slot_mut(&mut self, id: BackingId, nonce: u64) -> MonadResult<&mut BackingSlot<A>> {
        id.validate(nonce)?;
        let slot = self.slots.get_mut(id.slot as usize).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::StaleHandle,
                u64::from(id.slot),
            )
        })?;
        if slot.generation != id.generation || slot.object.is_none() {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::StaleHandle,
                id.generation,
            ));
        }
        Ok(slot)
    }

    pub(super) fn allocate(
        &mut self,
        page_count: u32,
        nonce: u64,
        max_physical_bits: u8,
        immutable: bool,
    ) -> MonadResult<BackingId> {
        let requested = page_count as usize;
        if requested == 0
            || requested > MAX_BACKING_PAGES
            || self
                .live_pages
                .checked_add(requested)
                .is_none_or(|total| total > MAX_BACKING_PAGES)
        {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::BackingCapacity,
                u64::from(page_count),
            ));
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.object.is_none() && !slot.retired)
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::BackingCapacity,
                    self.live_pages as u64,
                )
            })?;
        let generation = match next_generation(self.slots[index].generation, ErrorPhase::DraftEdit)
        {
            Ok(generation) => generation,
            Err(error) => {
                self.slots[index].retired = true;
                return Err(error);
            }
        };
        let id = BackingId {
            slot: index as u32,
            generation,
            session_nonce: nonce,
        };
        let mut pages: Vec<BackingPage<A::Allocation>> = Vec::new();
        pages.try_reserve_exact(requested).map_err(|_| {
            MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::AllocationFailure,
                u64::from(page_count),
            )
        })?;
        for _ in 0..requested {
            let (mut allocation, hpa) = match self.allocator.allocate_page(max_physical_bits) {
                Ok(page) => page,
                Err(error) => {
                    while let Some(page) = pages.pop() {
                        self.allocator.free_page(page.allocation);
                    }
                    return Err(error);
                }
            };
            A::bytes_mut(&mut allocation).fill(0);
            pages.push(BackingPage { allocation, hpa });
        }
        self.live_pages = self.live_pages.checked_add(requested).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::BackingCapacity,
                requested as u64,
            )
        })?;
        self.slots[index].generation = generation;
        self.slots[index].object = Some(BackingObject {
            id,
            pages,
            state: if immutable {
                BackingState::Immutable
            } else {
                BackingState::Mutable
            },
            draft_refs: 0,
            published_refs: 0,
            target_pinned: false,
        });
        Ok(id)
    }

    pub(super) fn page_hpa(
        &self,
        reference: BackingPageReference,
        nonce: u64,
    ) -> MonadResult<HostPhysicalAddress> {
        let object = self
            .slot(reference.backing_id, nonce)?
            .object
            .as_ref()
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::StaleHandle,
                    reference.backing_id.generation,
                )
            })?;
        if object.id != reference.backing_id {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::StaleHandle,
                reference.backing_id.generation,
            ));
        }
        object
            .pages
            .get(reference.page_index as usize)
            .map(|page| page.hpa)
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::InvalidRange,
                    u64::from(reference.page_index),
                )
            })
    }

    pub(super) fn write(
        &mut self,
        id: BackingId,
        nonce: u64,
        offset: usize,
        data: &[u8],
    ) -> MonadResult<()> {
        let slot = self.slot_mut(id, nonce)?;
        let object = slot.object.as_mut().ok_or_else(|| {
            MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
        })?;
        if object.state != BackingState::Mutable {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::WrongObjectState,
                object.state as u64,
            ));
        }
        let total = object
            .pages
            .len()
            .checked_mul(PAGE_SIZE_4K as usize)
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::AddressOverflow,
                    object.pages.len() as u64,
                )
            })?;
        let end = offset.checked_add(data.len()).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::AddressOverflow,
                offset as u64,
            )
        })?;
        if end > total {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::InvalidRange,
                end as u64,
            ));
        }
        let mut copied = 0usize;
        while copied < data.len() {
            let absolute = offset.checked_add(copied).ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::AddressOverflow,
                    offset as u64,
                )
            })?;
            let page_index = absolute / PAGE_SIZE_4K as usize;
            let page_offset = absolute % PAGE_SIZE_4K as usize;
            let amount = (PAGE_SIZE_4K as usize - page_offset).min(data.len() - copied);
            let page = &mut object.pages[page_index];
            A::bytes_mut(&mut page.allocation)[page_offset..page_offset + amount]
                .copy_from_slice(&data[copied..copied + amount]);
            copied += amount;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn snapshot_page(
        &self,
        id: BackingId,
        nonce: u64,
        page_index: u32,
    ) -> MonadResult<&[u8; PAGE_SIZE_4K as usize]> {
        let object = self
            .slot(id, nonce)?
            .object
            .as_ref()
            .ok_or_else(|| MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, 0))?;
        object
            .pages
            .get(page_index as usize)
            .map(|page| A::bytes(&page.allocation))
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::InvalidRange,
                    u64::from(page_index),
                )
            })
    }

    pub(super) fn adjust_draft_refs(
        &mut self,
        refs: &[BackingPageReference],
        nonce: u64,
        add: bool,
    ) -> MonadResult<()> {
        self.adjust_refs(refs, nonce, add, false)
    }

    pub(super) fn adjust_published_refs(
        &mut self,
        refs: &[BackingPageReference],
        nonce: u64,
        add: bool,
    ) -> MonadResult<()> {
        self.adjust_refs(refs, nonce, add, true)
    }

    fn adjust_refs(
        &mut self,
        refs: &[BackingPageReference],
        nonce: u64,
        add: bool,
        published: bool,
    ) -> MonadResult<()> {
        for reference in refs {
            let object = self
                .slot(reference.backing_id, nonce)?
                .object
                .as_ref()
                .ok_or_else(|| MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, 0))?;
            if reference.page_index as usize >= object.pages.len() {
                return Err(MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::InvalidRange,
                    u64::from(reference.page_index),
                ));
            }
            let count = if published {
                object.published_refs
            } else {
                object.draft_refs
            };
            let valid = if add {
                count.checked_add(1).is_some()
            } else {
                count.checked_sub(1).is_some()
            };
            if !valid {
                return Err(MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::EptVerificationFailure,
                    u64::from(count),
                ));
            }
        }
        for reference in refs {
            let slot = self.slot_mut(reference.backing_id, nonce)?;
            let object = slot
                .object
                .as_mut()
                .ok_or_else(|| MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, 0))?;
            let count = if published {
                &mut object.published_refs
            } else {
                &mut object.draft_refs
            };
            *count = if add {
                count.checked_add(1).ok_or_else(|| {
                    MonadError::new(
                        ErrorPhase::DraftEdit,
                        ErrorCode::BackingCapacity,
                        u64::from(*count),
                    )
                })?
            } else {
                count.checked_sub(1).ok_or_else(|| {
                    MonadError::new(
                        ErrorPhase::DraftEdit,
                        ErrorCode::EptVerificationFailure,
                        u64::from(*count),
                    )
                })?
            };
            if published && add {
                object.state = BackingState::PublishedPinned;
            }
        }
        Ok(())
    }

    pub(super) fn pin_target(&mut self, id: BackingId, nonce: u64) -> MonadResult<()> {
        let object = self.slot_mut(id, nonce)?.object.as_mut().ok_or_else(|| {
            MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
        })?;
        object.target_pinned = true;
        Ok(())
    }

    pub(super) fn free(&mut self, id: BackingId, nonce: u64) -> MonadResult<()> {
        let index = id.slot as usize;
        let slot = self.slot_mut(id, nonce)?;
        let object = slot.object.as_ref().ok_or_else(|| {
            MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
        })?;
        if object.target_pinned || object.draft_refs != 0 || object.published_refs != 0 {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::BackingStillReferenced,
                u64::from(object.draft_refs) | (u64::from(object.published_refs) << 32),
            ));
        }
        let mut object = self.slots[index].object.take().ok_or_else(|| {
            MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
        })?;
        self.live_pages = self
            .live_pages
            .checked_sub(object.pages.len())
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::EptVerificationFailure,
                    object.pages.len() as u64,
                )
            })?;
        while let Some(page) = object.pages.pop() {
            self.allocator.free_page(page.allocation);
        }
        Ok(())
    }

    pub(super) fn state(&self, id: BackingId, nonce: u64) -> MonadResult<BackingState> {
        self.slot(id, nonce)?
            .object
            .as_ref()
            .map(|object| object.state)
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::DraftEdit, ErrorCode::StaleHandle, id.generation)
            })
    }

    pub(super) fn release_all(&mut self) {
        for slot in &mut self.slots {
            if let Some(mut object) = slot.object.take() {
                while let Some(page) = object.pages.pop() {
                    self.allocator.free_page(page.allocation);
                }
            }
        }
        self.live_pages = 0;
    }

    #[cfg(test)]
    pub(super) fn counts(&self, id: BackingId) -> Option<(u32, u32, BackingState)> {
        let object = self.slots.get(id.slot as usize)?.object.as_ref()?;
        Some((object.draft_refs, object.published_refs, object.state))
    }
}

impl<A: EptPageAllocator + Clone> Drop for BackingRegistry<A> {
    fn drop(&mut self) {
        self.release_all();
    }
}
