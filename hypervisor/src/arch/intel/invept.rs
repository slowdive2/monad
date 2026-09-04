use core::arch::asm;

use crate::error::MonadResult;

use super::vmx::{decode_vmx_status, vmread, VmxOperation};

const INVEPT_SINGLE_CONTEXT: u64 = 1;
const INVEPT_ALL_CONTEXTS: u64 = 2;

#[repr(C, align(16))]
struct InveptDescriptor {
    eptp: u64,
    reserved: u64,
}

unsafe fn raw_invept(kind: u64, descriptor: &InveptDescriptor) -> u64 {
    let flags: u64;
    // SAFETY: the descriptor is 16 bytes and aligned; startup checked the type.
    unsafe {
        asm!(
            "invept {kind}, [{descriptor}]",
            "pushfq",
            "pop {flags}",
            kind = in(reg) kind,
            descriptor = in(reg) descriptor,
            flags = lateout(reg) flags,
        );
    }
    flags
}

fn instruction_error(flags: u64) -> Option<u32> {
    if flags & (1 << 6) == 0 {
        return None;
    }
    vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR)
        .ok()
        .map(|value| value as u32)
}

/// Invalidates translations from one checked EPTP.
///
/// # Safety
///
/// The caller is in VMX root with single-context INVEPT support. `eptp` names a
/// published view.
pub unsafe fn invept_single(eptp: u64) -> MonadResult<()> {
    let descriptor = InveptDescriptor { eptp, reserved: 0 };
    // SAFETY: the caller and checked descriptor uphold the contract.
    let flags = unsafe { raw_invept(INVEPT_SINGLE_CONTEXT, &descriptor) };
    decode_vmx_status(VmxOperation::InveptSingle, flags, instruction_error(flags))
}

/// Invalidates translations from every EPTP.
///
/// # Safety
///
/// The caller is in VMX root with all-context INVEPT support.
pub unsafe fn invept_all() -> MonadResult<()> {
    let descriptor = InveptDescriptor {
        eptp: 0,
        reserved: 0,
    };
    // SAFETY: the caller upholds the contract; the descriptor is zeroed.
    let flags = unsafe { raw_invept(INVEPT_ALL_CONTEXTS, &descriptor) };
    decode_vmx_status(VmxOperation::InveptAll, flags, instruction_error(flags))
}
