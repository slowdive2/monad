//! windows ram discovery for the identity ept view.

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::null_mut;

use windows_sys::Wdk::System::SystemServices::{
    ExFreePool, MmGetPhysicalMemoryRangesEx2, PHYSICAL_MEMORY_RANGE,
};

use crate::ept::{PhysicalRange, PhysicalRangeKind, RequiredPhysicalRange};
use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

/// owns the pool allocation returned by `MmGetPhysicalMemoryRangesEx2`.
struct PhysicalMemoryRanges(*mut PHYSICAL_MEMORY_RANGE);

impl Drop for PhysicalMemoryRanges {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // safety: windows returns a single pool allocation that must be
            // released with exfreepool after the zero-terminated array is read.
            unsafe { ExFreePool(self.0.cast()) };
        }
    }
}

/// combines the windows ram snapshot with controller-supplied device ranges.
pub(crate) fn collect_physical_inventory(
    device_ranges: &[PhysicalRange],
) -> MonadResult<(Vec<PhysicalRange>, Vec<RequiredPhysicalRange>)> {
    // safety: a null partition selects the current system partition. zero
    // flags request the documented snapshot form of the api.
    let allocation = PhysicalMemoryRanges(unsafe { MmGetPhysicalMemoryRangesEx2(null_mut(), 0) });
    if allocation.0.is_null() {
        return Err(MonadError::new(
            ErrorPhase::EptBuild,
            ErrorCode::AllocationFailure,
            0,
        ));
    }

    let mut inventory = Vec::new();
    inventory.try_reserve(device_ranges.len()).map_err(|_| {
        MonadError::new(
            ErrorPhase::EptBuild,
            ErrorCode::AllocationFailure,
            device_ranges.len() as u64,
        )
    })?;

    let mut index = 0usize;
    loop {
        // safety: the documented result is a zero-terminated array owned by
        // `allocation`, which remains alive for the duration of this loop.
        let range = unsafe { *allocation.0.add(index) };
        if range.BaseAddress == 0 && range.NumberOfBytes == 0 {
            break;
        }
        if range.BaseAddress < 0 || range.NumberOfBytes <= 0 {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::InvalidRange,
                index as u64,
            ));
        }

        inventory.try_reserve(1).map_err(|_| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::AllocationFailure,
                index as u64,
            )
        })?;
        inventory.push(PhysicalRange {
            start: range.BaseAddress as u64,
            length: range.NumberOfBytes as u64,
            kind: PhysicalRangeKind::Memory,
        });
        index = index.checked_add(1).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::AddressOverflow,
                index as u64,
            )
        })?;
    }

    let mut required = Vec::new();
    required
        .try_reserve_exact(device_ranges.len())
        .map_err(|_| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::AllocationFailure,
                device_ranges.len() as u64,
            )
        })?;

    for (index, range) in device_ranges.iter().copied().enumerate() {
        if range.kind != PhysicalRangeKind::Device {
            return Err(MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::InvalidRange,
                index as u64,
            ));
        }

        inventory.try_reserve(1).map_err(|_| {
            MonadError::new(
                ErrorPhase::EptBuild,
                ErrorCode::AllocationFailure,
                index as u64,
            )
        })?;
        inventory.push(range);
        required.push(RequiredPhysicalRange {
            start: range.start,
            length: range.length,
        });
    }

    Ok((inventory, required))
}
