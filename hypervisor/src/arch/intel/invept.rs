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
    // safety: the descriptor is 16 bytes and aligned; startup checked the type.
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

/// drops cached translations for a published eptp.
///
/// # Safety
///
/// the caller is in vmx root with single-context invept support. `eptp` names a
/// published view.
pub unsafe fn invept_single(eptp: u64) -> MonadResult<()> {
    let descriptor = InveptDescriptor { eptp, reserved: 0 };
    // safety: startup checked support; the eptp and descriptor are valid.
    let flags = unsafe { raw_invept(INVEPT_SINGLE_CONTEXT, &descriptor) };
    decode_vmx_status(VmxOperation::InveptSingle, flags, instruction_error(flags))
}

/// invalidates translations from every eptp.
///
/// # Safety
///
/// the caller is in vmx root with all-context invept support.
pub unsafe fn invept_all() -> MonadResult<()> {
    let descriptor = InveptDescriptor {
        eptp: 0,
        reserved: 0,
    };
    // safety: startup checked support; all reserved bits are zero.
    let flags = unsafe { raw_invept(INVEPT_ALL_CONTEXTS, &descriptor) };
    decode_vmx_status(VmxOperation::InveptAll, flags, instruction_error(flags))
}
