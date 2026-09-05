use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use wdk_sys::{
    ntddk::{ExAllocatePool2, ExFreePoolWithTag},
    POOL_FLAG_NON_PAGED,
};

#[cfg_attr(test, allow(dead_code))]
pub struct KernelAllocator;
#[cfg_attr(test, allow(dead_code))]
const TAG: u32 = u32::from_le_bytes(*b"Mnal");
const POOL_ALIGNMENT: usize = 16;
const PREFIX: usize = core::mem::size_of::<usize>();

fn allocation_size(layout: Layout) -> Option<usize> {
    if layout.align() <= POOL_ALIGNMENT {
        Some(layout.size())
    } else {
        layout
            .size()
            .checked_add(layout.align() - 1)?
            .checked_add(PREFIX)
    }
}

fn aligned_address(base: usize, alignment: usize) -> Option<usize> {
    base.checked_add(PREFIX)?
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

// safety: every successful allocation satisfies Layout; the original pool pointer
// is retained outside the caller's bytes and recovered under the same Layout.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(size) = allocation_size(layout) else {
            return null_mut();
        };
        let base = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, size as u64, TAG).cast::<u8>() };
        if base.is_null() || layout.align() <= POOL_ALIGNMENT {
            return base;
        }
        let Some(address) = aligned_address(base as usize, layout.align()) else {
            unsafe {
                ExFreePoolWithTag(base.cast(), TAG);
            }
            return null_mut();
        };
        let result = address as *mut u8;
        unsafe {
            result.sub(PREFIX).cast::<*mut u8>().write_unaligned(base);
        }
        result
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let base = if layout.align() <= POOL_ALIGNMENT {
            pointer
        } else {
            unsafe { pointer.sub(PREFIX).cast::<*mut u8>().read_unaligned() }
        };
        unsafe {
            ExFreePoolWithTag(base.cast(), TAG);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn over_aligned_allocations_leave_room_for_payload_and_owner() {
        for alignment in [32, 64, 256, 4096, 8192] {
            for size in [1, 128, 1152, 8192] {
                let layout = Layout::from_size_align(size, alignment).expect("layout");
                for base in (0x1000..0x3000).step_by(16) {
                    let address = aligned_address(base, alignment).expect("address");
                    assert_eq!(address % alignment, 0);
                    assert!(address >= base + PREFIX);
                    assert!(address + size <= base + allocation_size(layout).expect("size"));
                }
            }
        }
        assert!(aligned_address(usize::MAX, 64).is_none());
    }
}
