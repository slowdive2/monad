extern crate alloc;

use alloc::vec::Vec;
use core::{ffi::c_void, ptr, ptr::NonNull};

use wdk_sys::{
    ntddk::{
        KeGetCurrentIrql, MmAllocateContiguousMemorySpecifyCache, MmFreeContiguousMemory,
        MmGetPhysicalAddress,
    },
    _MEMORY_CACHING_TYPE::MmCached,
    PHYSICAL_ADDRESS,
};

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

use super::{HostPhysicalAddress, PAGE_SIZE_4K};

const PASSIVE_LEVEL: u8 = 0;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptPageKind {
    Pml4 = 1,
    Pdpt = 2,
    Pd = 3,
    Pt = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptPageOwner {
    BaseBuild = 1,
    Draft = 2,
    Published = 3,
}

#[repr(C, align(4096))]
pub struct EptTablePage {
    entries: [u64; 512],
}

impl EptTablePage {
    #[cfg(test)]
    const fn zeroed() -> Self {
        Self { entries: [0; 512] }
    }
}

const _: () = {
    assert!(core::mem::size_of::<EptTablePage>() == PAGE_SIZE_4K as usize);
    assert!(core::mem::align_of::<EptTablePage>() == PAGE_SIZE_4K as usize);
};

pub trait EptPageAllocator {
    type Allocation;

    fn allocate_page(
        &mut self,
        max_physical_bits: u8,
    ) -> MonadResult<(Self::Allocation, HostPhysicalAddress)>;

    fn entries(allocation: &Self::Allocation) -> &[u64; 512];

    fn entries_mut(allocation: &mut Self::Allocation) -> &mut [u64; 512];

    fn bytes(allocation: &Self::Allocation) -> &[u8; PAGE_SIZE_4K as usize];

    fn bytes_mut(allocation: &mut Self::Allocation) -> &mut [u8; PAGE_SIZE_4K as usize];

    fn free_page(&mut self, allocation: Self::Allocation);
}

pub struct WindowsPageAllocation(NonNull<EptTablePage>);

#[derive(Clone, Copy)]
pub struct WindowsPageAllocator;

impl EptPageAllocator for WindowsPageAllocator {
    type Allocation = WindowsPageAllocation;

    fn allocate_page(
        &mut self,
        max_physical_bits: u8,
    ) -> MonadResult<(Self::Allocation, HostPhysicalAddress)> {
        // SAFETY: this pointer-free query only checks the caller's irql.
        if unsafe { KeGetCurrentIrql() } != PASSIVE_LEVEL {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::InvalidLifecycleState,
                0,
            ));
        }
        if !(12..=48).contains(&max_physical_bits) {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::PhysicalAddressTooWide,
                u64::from(max_physical_bits),
            ));
        }
        let limit = 1u64 << max_physical_bits;
        let low = PHYSICAL_ADDRESS { QuadPart: 0 };
        let high = PHYSICAL_ADDRESS {
            QuadPart: (limit - 1) as i64,
        };
        let boundary = PHYSICAL_ADDRESS { QuadPart: 0 };
        // SAFETY: this runs at PASSIVE_LEVEL and asks Windows for one cached,
        // Physically contiguous page below the checked address limit.
        let raw = unsafe {
            MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE_4K, low, high, boundary, MmCached)
        };
        let Some(pointer) = NonNull::new(raw.cast::<EptTablePage>()) else {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptAllocationFailure,
                0,
            ));
        };
        // SAFETY: Windows returned a writable allocation of exactly one page.
        unsafe { ptr::write_bytes(pointer.as_ptr().cast::<u8>(), 0, PAGE_SIZE_4K as usize) };
        // SAFETY: the pointer names the allocation returned above.
        let physical = unsafe { MmGetPhysicalAddress(pointer.as_ptr().cast::<c_void>()).QuadPart };
        let hpa = match HostPhysicalAddress::for_mapping(
            physical as u64,
            PAGE_SIZE_4K,
            PAGE_SIZE_4K,
            max_physical_bits,
        ) {
            Ok(hpa) if pointer.as_ptr() as usize & (PAGE_SIZE_4K as usize - 1) == 0 => hpa,
            _ => {
                // SAFETY: this allocation has not escaped and is freed once.
                unsafe { MmFreeContiguousMemory(pointer.as_ptr().cast()) };
                return Err(MonadError::new(
                    ErrorPhase::EptBuild,
                    ErrorCode::MisalignedAddress,
                    physical as u64,
                ));
            }
        };
        Ok((WindowsPageAllocation(pointer), hpa))
    }

    fn entries(allocation: &Self::Allocation) -> &[u64; 512] {
        // SAFETY: the token owns a live page for the whole borrow.
        unsafe { &allocation.0.as_ref().entries }
    }

    fn entries_mut(allocation: &mut Self::Allocation) -> &mut [u64; 512] {
        // SAFETY: the mutable token owns the page exclusively.
        unsafe { &mut allocation.0.as_mut().entries }
    }

    fn bytes(allocation: &Self::Allocation) -> &[u8; PAGE_SIZE_4K as usize] {
        // SAFETY: the allocation is exactly one live aligned page.
        unsafe { &*allocation.0.as_ptr().cast::<[u8; PAGE_SIZE_4K as usize]>() }
    }

    fn bytes_mut(allocation: &mut Self::Allocation) -> &mut [u8; PAGE_SIZE_4K as usize] {
        // SAFETY: the token owns the full page exclusively.
        unsafe { &mut *allocation.0.as_ptr().cast::<[u8; PAGE_SIZE_4K as usize]>() }
    }

    fn free_page(&mut self, allocation: Self::Allocation) {
        // SAFETY: the token is consumed, so the page is freed once.
        unsafe { MmFreeContiguousMemory(allocation.0.as_ptr().cast()) };
    }
}

struct OwnedTablePage<T> {
    allocation: T,
    hpa: HostPhysicalAddress,
    kind: EptPageKind,
    owner: EptPageOwner,
}

pub struct EptPageStore<A: EptPageAllocator> {
    allocator: A,
    pages: Vec<OwnedTablePage<A::Allocation>>,
    max_physical_bits: u8,
}

impl<A: EptPageAllocator> EptPageStore<A> {
    pub fn new(allocator: A, max_physical_bits: u8) -> MonadResult<Self> {
        if !(12..=48).contains(&max_physical_bits) {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::PhysicalAddressTooWide,
                u64::from(max_physical_bits),
            ));
        }
        Ok(Self {
            allocator,
            pages: Vec::new(),
            max_physical_bits,
        })
    }

    pub(super) fn allocate(
        &mut self,
        kind: EptPageKind,
        owner: EptPageOwner,
    ) -> MonadResult<HostPhysicalAddress> {
        self.pages.try_reserve(1).map_err(|_| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptAllocationFailure,
                kind as u64,
            )
        })?;
        let (allocation, hpa) = self.allocator.allocate_page(self.max_physical_bits)?;
        if self.pages.iter().any(|page| page.hpa == hpa) {
            self.allocator.free_page(allocation);
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptVerificationFailure,
                hpa.get(),
            ));
        }
        self.pages.push(OwnedTablePage {
            allocation,
            hpa,
            kind,
            owner,
        });
        Ok(hpa)
    }

    fn find_index(&self, hpa: HostPhysicalAddress) -> Option<usize> {
        self.pages.iter().position(|page| page.hpa == hpa)
    }

    pub(super) fn page(
        &self,
        hpa: HostPhysicalAddress,
    ) -> Option<(EptPageKind, EptPageOwner, &[u64; 512])> {
        let page = self.pages.get(self.find_index(hpa)?)?;
        Some((page.kind, page.owner, A::entries(&page.allocation)))
    }

    pub(super) fn read_entry(&self, hpa: HostPhysicalAddress, index: usize) -> MonadResult<u64> {
        let (_, _, entries) = self.page(hpa).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptVerificationFailure,
                hpa.get(),
            )
        })?;
        entries.get(index).copied().ok_or_else(|| {
            MonadError::new(ErrorPhase::EptBuild, ErrorCode::InvalidRange, index as u64)
        })
    }

    pub(super) fn write_entry(
        &mut self,
        hpa: HostPhysicalAddress,
        index: usize,
        raw: u64,
    ) -> MonadResult<()> {
        let page_index = self.find_index(hpa).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::EptVerificationFailure,
                hpa.get(),
            )
        })?;
        let entry = A::entries_mut(&mut self.pages[page_index].allocation)
            .get_mut(index)
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::EptBuild, ErrorCode::InvalidRange, index as u64)
            })?;
        *entry = raw;
        Ok(())
    }

    pub(super) fn len(&self) -> usize {
        self.pages.len()
    }

    pub(super) fn page_at(
        &self,
        index: usize,
    ) -> Option<(HostPhysicalAddress, EptPageKind, EptPageOwner, &[u64; 512])> {
        let page = self.pages.get(index)?;
        Some((
            page.hpa,
            page.kind,
            page.owner,
            A::entries(&page.allocation),
        ))
    }

    pub(super) fn set_owner_all(&mut self, owner: EptPageOwner) {
        for page in &mut self.pages {
            page.owner = owner;
        }
    }
}

impl<A: EptPageAllocator + Clone> EptPageStore<A> {
    pub(super) fn allocator_clone(&self) -> A {
        self.allocator.clone()
    }
}

impl<A: EptPageAllocator> Drop for EptPageStore<A> {
    fn drop(&mut self) {
        while let Some(page) = self.pages.pop() {
            self.allocator.free_page(page.allocation);
        }
    }
}

#[cfg(test)]
pub(super) mod fake {
    extern crate alloc;

    use alloc::{boxed::Box, rc::Rc};
    use core::cell::Cell;

    use super::*;

    #[derive(Default)]
    pub struct FakePageStats {
        pub allocated: Cell<usize>,
        pub freed: Cell<usize>,
    }

    pub struct FakeAllocation(Box<EptTablePage>);

    struct FakePageState {
        next_hpa: Cell<u64>,
        allocation_ordinal: Cell<usize>,
        fail_at: Cell<Option<usize>>,
    }

    #[derive(Clone)]
    pub struct FakePageAllocator {
        state: Rc<FakePageState>,
        pub stats: Rc<FakePageStats>,
    }

    impl FakePageAllocator {
        pub fn new(start_hpa: u64, fail_at: Option<usize>) -> Self {
            Self {
                state: Rc::new(FakePageState {
                    next_hpa: Cell::new(start_hpa),
                    allocation_ordinal: Cell::new(0),
                    fail_at: Cell::new(fail_at),
                }),
                stats: Rc::new(FakePageStats::default()),
            }
        }

        pub fn fail_at(&self, ordinal: Option<usize>) {
            self.state.fail_at.set(ordinal);
        }

        pub fn allocation_ordinal(&self) -> usize {
            self.state.allocation_ordinal.get()
        }
    }

    impl EptPageAllocator for FakePageAllocator {
        type Allocation = FakeAllocation;

        fn allocate_page(
            &mut self,
            max_physical_bits: u8,
        ) -> MonadResult<(Self::Allocation, HostPhysicalAddress)> {
            let ordinal = self.state.allocation_ordinal.get();
            self.state
                .allocation_ordinal
                .set(ordinal.checked_add(1).ok_or_else(|| {
                    MonadError::new(
                        ErrorPhase::EptBuild,
                        ErrorCode::AddressOverflow,
                        ordinal as u64,
                    )
                })?);
            if self.state.fail_at.get() == Some(ordinal) {
                return Err(MonadError::new(
                    ErrorPhase::EptBuild,
                    ErrorCode::EptAllocationFailure,
                    ordinal as u64,
                ));
            }
            let hpa = HostPhysicalAddress::for_mapping(
                self.state.next_hpa.get(),
                PAGE_SIZE_4K,
                PAGE_SIZE_4K,
                max_physical_bits,
            )?;
            self.state.next_hpa.set(
                self.state
                    .next_hpa
                    .get()
                    .checked_add(PAGE_SIZE_4K)
                    .ok_or_else(|| {
                        MonadError::new(
                            ErrorPhase::EptBuild,
                            ErrorCode::AddressOverflow,
                            self.state.next_hpa.get(),
                        )
                    })?,
            );
            self.stats.allocated.set(self.stats.allocated.get() + 1);
            Ok((FakeAllocation(Box::new(EptTablePage::zeroed())), hpa))
        }

        fn entries(allocation: &Self::Allocation) -> &[u64; 512] {
            &allocation.0.entries
        }

        fn entries_mut(allocation: &mut Self::Allocation) -> &mut [u64; 512] {
            &mut allocation.0.entries
        }

        fn bytes(allocation: &Self::Allocation) -> &[u8; PAGE_SIZE_4K as usize] {
            // SAFETY: the boxed table is one initialized page.
            unsafe { &*core::ptr::from_ref(&*allocation.0).cast::<[u8; PAGE_SIZE_4K as usize]>() }
        }

        fn bytes_mut(allocation: &mut Self::Allocation) -> &mut [u8; PAGE_SIZE_4K as usize] {
            // SAFETY: the box owns the full page exclusively.
            unsafe {
                &mut *core::ptr::from_mut(&mut *allocation.0).cast::<[u8; PAGE_SIZE_4K as usize]>()
            }
        }

        fn free_page(&mut self, _allocation: Self::Allocation) {
            self.stats.freed.set(self.stats.freed.get() + 1);
        }
    }
}
