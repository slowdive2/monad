#![no_std]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use allocator::KernelAllocator;
#[cfg(not(test))]
use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS};

mod allocator;
pub mod device;
pub mod ioctl;
pub mod session;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

#[cfg(not(test))]
#[export_name = "DriverEntry"]
/// starts the driver and gives unload ownership to windows.
///
/// # Safety
///
/// windows supplies a unique driver object and valid registry path under the
/// wdm entry contract.
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    if hypervisor::logging::init(log::LevelFilter::Info).is_err() {
        return 0xC000_0001u32 as i32;
    }
    let status = unsafe { device::create(driver) };
    if status < 0 {
        return status;
    }
    driver.DriverUnload = Some(driver_exit);
    STATUS_SUCCESS
}

#[cfg(not(test))]
unsafe extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    unsafe {
        hypervisor::vmm::shutdown_and_release();
    }
    unsafe { device::destroy(driver) };
}
