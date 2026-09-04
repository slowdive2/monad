// Based on https://github.com/tandasat/Hypervisor-101-in-Rust/blob/main/hypervisor/src/hardware_vt/vmx_run_vm.S
// And https://github.com/daaximus
// And https://github.com/drew-gpf

// SPDX-License-Identifier: MIT
// Copyright (c) 2022 memN0ps
// This file is derived from the illusion-rs project:
// Https://github.com/memN0ps/illusion-rs
// Https://github.com/memN0ps/illusion-rs/blob/main/hypervisor/src/intel/vmlaunch.rs

use core::{arch::global_asm, mem};

use x86::vmx::VmFail;

#[cfg(test)]
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::{
    error::{ErrorCode, ErrorPhase, MonadError, MonadResult},
    vmm::Vcpu,
};

use super::{
    caps::{IntelCapabilities, VmxonPermit},
    state::{read_cr0, read_cr4, write_cr0, write_cr4},
    vmcs::GuestRegs,
};

pub const VMX_REGION_SIZE: usize = 0x1000;

#[repr(C, align(4096))]
pub struct VmxRegion {
    pub header: u32,
    pub abort_indicator: u32,
    pub data: [u8; VMX_REGION_SIZE - 8],
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxOperation {
    Vmxon = 1,
    Vmxoff = 2,
    Vmclear = 3,
    Vmptrld = 4,
    Vmread = 5,
    Vmwrite = 6,
    Vmlaunch = 7,
    Vmresume = 8,
    InveptSingle = 9,
    InveptAll = 10,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxStatus {
    Success = 0,
    VmfailInvalid = 1,
    VmfailValid = 2,
}

fn error_code(operation: VmxOperation) -> ErrorCode {
    match operation {
        VmxOperation::Vmread => ErrorCode::VmreadFailure,
        VmxOperation::Vmwrite => ErrorCode::VmwriteFailure,
        VmxOperation::InveptSingle | VmxOperation::InveptAll => ErrorCode::InveptFailure,
        _ => ErrorCode::VmxInstructionFailure,
    }
}

pub(crate) fn vmx_error(
    operation: VmxOperation,
    status: VmxStatus,
    instruction_error: Option<u32>,
) -> MonadError {
    let detail = (operation as u64)
        | ((status as u64) << 8)
        | (u64::from(instruction_error.unwrap_or(u32::MAX)) << 32);
    MonadError::new(ErrorPhase::Launch, error_code(operation), detail)
}

pub fn decode_vmx_status(
    operation: VmxOperation,
    rflags: u64,
    instruction_error: Option<u32>,
) -> MonadResult<()> {
    if rflags & (1 << 6) != 0 {
        Err(vmx_error(
            operation,
            VmxStatus::VmfailValid,
            instruction_error,
        ))
    } else if rflags & 1 != 0 {
        Err(vmx_error(operation, VmxStatus::VmfailInvalid, None))
    } else {
        Ok(())
    }
}

fn map_vmx_result(result: x86::vmx::Result<()>, operation: VmxOperation) -> MonadResult<()> {
    match result {
        Ok(()) => Ok(()),
        Err(VmFail::VmFailInvalid) => Err(vmx_error(operation, VmxStatus::VmfailInvalid, None)),
        Err(VmFail::VmFailValid) => {
            // safety: vmfailvalid means a current vmcs exists. a failed
            // diagnostic vmread leaves the subcode absent.
            let instruction_error =
                unsafe { x86::bits64::vmx::vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) }
                    .ok()
                    .map(|value| value as u32);
            Err(vmx_error(
                operation,
                VmxStatus::VmfailValid,
                instruction_error,
            ))
        }
    }
}

#[cfg(test)]
static FAIL_BEFORE_VMXON: AtomicBool = AtomicBool::new(false);

#[inline]
fn pre_vmxon_failpoint() -> MonadResult<()> {
    #[cfg(test)]
    if FAIL_BEFORE_VMXON.swap(false, Ordering::AcqRel) {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::VmxInstructionFailure,
            VmxOperation::Vmxon as u64,
        ));
    }
    Ok(())
}

pub(crate) fn vmxon(region: u64, _permit: VmxonPermit) -> MonadResult<()> {
    // this is the first vmxon. the permit means capability and topology
    // checks already passed.
    pre_vmxon_failpoint()?;
    // safety: the caller owns the checked vmxon region and stays on its cpu.
    map_vmx_result(
        unsafe { x86::bits64::vmx::vmxon(region) },
        VmxOperation::Vmxon,
    )
}

pub(crate) fn vmxoff() -> MonadResult<()> {
    // safety: this vcpu already entered vmx.
    map_vmx_result(unsafe { x86::bits64::vmx::vmxoff() }, VmxOperation::Vmxoff)
}

pub(crate) fn vmclear(region: u64) -> MonadResult<()> {
    // safety: region is this vcpu's aligned vmcs address.
    map_vmx_result(
        unsafe { x86::bits64::vmx::vmclear(region) },
        VmxOperation::Vmclear,
    )
}

pub(crate) fn vmptrld(region: u64) -> MonadResult<()> {
    // safety: region is this vcpu's initialized vmcs address.
    map_vmx_result(
        unsafe { x86::bits64::vmx::vmptrld(region) },
        VmxOperation::Vmptrld,
    )
}

pub(crate) fn vmread(field: u32) -> MonadResult<u64> {
    // safety: vmx root is active and `field` is an intel vmcs encoding.
    match unsafe { x86::bits64::vmx::vmread(field) } {
        Ok(value) => Ok(value),
        Err(VmFail::VmFailInvalid) => Err(vmx_error(
            VmxOperation::Vmread,
            VmxStatus::VmfailInvalid,
            None,
        )),
        Err(VmFail::VmFailValid) => {
            // safety: vmfailvalid guarantees a current vmcs; this reads its
            // instruction-error field.
            let instruction_error =
                unsafe { x86::bits64::vmx::vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR) }
                    .ok()
                    .map(|value| value as u32);
            Err(vmx_error(
                VmxOperation::Vmread,
                VmxStatus::VmfailValid,
                instruction_error,
            ))
        }
    }
}

pub(crate) fn vmwrite(field: u32, value: u64) -> MonadResult<()> {
    #[cfg(test)]
    if field == x86::vmx::vmcs::control::EPTP_FULL {
        EPTP_WRITE_COUNT.fetch_add(1, Ordering::AcqRel);
    }
    // safety: vmx root is active and `field` is an intel vmcs encoding.
    map_vmx_result(
        unsafe { x86::bits64::vmx::vmwrite(field, value) },
        VmxOperation::Vmwrite,
    )
}

#[cfg(test)]
static EPTP_WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn eptp_write_count_for_test() -> usize {
    EPTP_WRITE_COUNT.load(Ordering::Acquire)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalControlRegisters {
    pub cr0: u64,
    pub cr4: u64,
}

pub(crate) fn prepare_control_registers(
    capabilities: &IntelCapabilities,
) -> MonadResult<OriginalControlRegisters> {
    const CR4_VMXE: u64 = 1 << 13;
    let original = OriginalControlRegisters {
        cr0: read_cr0(),
        cr4: read_cr4(),
    };
    let adjusted_cr0 = (original.cr0 | capabilities.cr0_fixed0) & capabilities.cr0_fixed1;
    let adjusted_cr4 =
        (original.cr4 | capabilities.cr4_fixed0 | CR4_VMXE) & capabilities.cr4_fixed1;
    if adjusted_cr4 & CR4_VMXE == 0 {
        return Err(MonadError::new(
            ErrorPhase::Capability,
            ErrorCode::UnsupportedCapability,
            super::caps::RequiredCapability::Cr4FixedMasks as u64,
        ));
    }
    write_cr0(adjusted_cr0);
    write_cr4(adjusted_cr4);
    Ok(original)
}

pub(crate) fn restore_control_registers(original: OriginalControlRegisters) {
    write_cr0(original.cr0);
    write_cr4(original.cr4);
}

extern "efiapi" {
    // initial launch returns zero from `.launchsuccess` in vmx non-root mode.
    // vm-entry failure returns rflags; a successful
    // resume continues the guest and does not return here.
    #[link_name = "launch_vm"]
    fn raw_launch_vm(regs: &mut GuestRegs, launched: u64) -> u64;
    #[link_name = "restore_guest"]
    fn raw_restore_guest(regs: &GuestRegs, xsave_area: *const u8, xsave_mask: u64) -> !;
    #[link_name = "rendezvous_vmcall"]
    fn raw_rendezvous_vmcall();
    static rendezvous_vmcall_start: u8;
    static rendezvous_vmcall_end: u8;
    pub(crate) fn vmexit_entry();
}

unsafe fn enter_guest(regs: &mut GuestRegs, operation: VmxOperation) -> MonadResult<()> {
    let launched = operation == VmxOperation::Vmresume;
    // safety: the caller supplied the right vmcs state; assembly keeps the abi.
    let rflags = unsafe { raw_launch_vm(regs, u64::from(launched)) };
    let vmwrite_failed = rflags & (1 << 63) != 0;
    let operation = if vmwrite_failed {
        VmxOperation::Vmwrite
    } else {
        operation
    };
    let instruction_error = if rflags & (1 << 6) != 0 {
        vmread(x86::vmx::vmcs::ro::VM_INSTRUCTION_ERROR)
            .ok()
            .map(|value| value as u32)
    } else {
        None
    };
    decode_vmx_status(operation, rflags & !(1 << 63), instruction_error)
}

/// enters a clear vmcs with vmlaunch.
///
/// # Safety
///
/// the caller is in vmx root with a current initialized clear vmcs and live
/// register storage.
pub unsafe fn vmlaunch(regs: &mut GuestRegs) -> MonadResult<()> {
    // safety: the vmcs state matches the requested entry.
    unsafe { enter_guest(regs, VmxOperation::Vmlaunch) }
}

/// re-enters a launched vmcs with vmresume.
///
/// # Safety
///
/// the caller is in vmx root with a current vmcs in the launched state and must
/// provide its live register storage.
pub unsafe fn vmresume(regs: &mut GuestRegs) -> MonadResult<()> {
    // safety: the vmcs state matches the requested entry.
    unsafe { enter_guest(regs, VmxOperation::Vmresume) }
}

/// restores captured guest registers after vmxoff.
///
/// # Safety
///
/// `regs` holds a canonical rip/rsp pair from this guest. vmx has ended here.
pub unsafe fn restore_guest(regs: &GuestRegs, xsave_area: *const u8, xsave_mask: u64) -> ! {
    // safety: vmx is off, the registers are captured, and this never returns.
    unsafe { raw_restore_guest(regs, xsave_area, xsave_mask) }
}

/// issues the private vmcall from its rendezvous callback.
///
/// # Safety
///
/// the caller runs at `IPI_LEVEL` in this vcpu's callback after publishing its
/// prepared mailbox.
pub unsafe fn rendezvous_vmcall() {
    // safety: the caller establishes the accepted mailbox transition.
    unsafe { raw_rendezvous_vmcall() };
}

pub fn rendezvous_vmcall_bounds() -> (u64, u64) {
    (
        core::ptr::addr_of!(rendezvous_vmcall_start) as u64,
        core::ptr::addr_of!(rendezvous_vmcall_end) as u64,
    )
}

global_asm!(
    r#"

.global rendezvous_vmcall
.global rendezvous_vmcall_start
.global rendezvous_vmcall_end
rendezvous_vmcall:
rendezvous_vmcall_start:
    vmcall
rendezvous_vmcall_end:
    ret


.macro PUSHAQ
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
.endm


.macro POPAQ
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
.endm


.macro SAVE_XMM
    sub rsp, 0x100

    movaps xmmword ptr [rsp], xmm0
    movaps xmmword ptr [rsp + 0x10], xmm1
    movaps xmmword ptr [rsp + 0x20], xmm2
    movaps xmmword ptr [rsp + 0x30], xmm3
    movaps xmmword ptr [rsp + 0x40], xmm4
    movaps xmmword ptr [rsp + 0x50], xmm5
    movaps xmmword ptr [rsp + 0x60], xmm6
    movaps xmmword ptr [rsp + 0x70], xmm7
    movaps xmmword ptr [rsp + 0x80], xmm8
    movaps xmmword ptr [rsp + 0x90], xmm9
    movaps xmmword ptr [rsp + 0xA0], xmm10
    movaps xmmword ptr [rsp + 0xB0], xmm11
    movaps xmmword ptr [rsp + 0xC0], xmm12
    movaps xmmword ptr [rsp + 0xD0], xmm13
    movaps xmmword ptr [rsp + 0xE0], xmm14
    movaps xmmword ptr [rsp + 0xF0], xmm15
.endm


.macro RESTORE_XMM
movaps xmm0, xmmword ptr [rsp]
    movaps xmm1, xmmword ptr [rsp + 0x10]
    movaps xmm2, xmmword ptr [rsp + 0x20]
    movaps xmm3, xmmword ptr [rsp + 0x30]
    movaps xmm4, xmmword ptr [rsp + 0x40]
    movaps xmm5, xmmword ptr [rsp + 0x50]
    movaps xmm6, xmmword ptr [rsp + 0x60]
    movaps xmm7, xmmword ptr [rsp + 0x70]
    movaps xmm8, xmmword ptr [rsp + 0x80]
    movaps xmm9, xmmword ptr [rsp + 0x90]
    movaps xmm10, xmmword ptr [rsp + 0xA0]
    movaps xmm11, xmmword ptr [rsp + 0xB0]
    movaps xmm12, xmmword ptr [rsp + 0xC0]
    movaps xmm13, xmmword ptr [rsp + 0xD0]
    movaps xmm14, xmmword ptr [rsp + 0xE0]
    movaps xmm15, xmmword ptr [rsp + 0xF0]

    add rsp, 0x100
.endm

.global launch_vm
launch_vm:
    PUSHAQ

    SAVE_XMM

    mov     r15, rcx    // regs ptr
    mov     r14, rdx    // launch flag
    push    rcx         // keep regs ptr across vm entry

    mov     r13, r15
    sub     r13, {vcpu_regs}
    mov     r12, [r13 + {vcpu_xsave_area}]
    test    r14, r14
    jne     .RestoreExtended
    mov     rax, [r13 + {vcpu_xsave_mask}]
    mov     rdx, rax
    shr     rdx, 32
    xsaves64 [r12]

.RestoreExtended:
    mov     rax, [r13 + {vcpu_xsave_mask}]
    mov     rdx, rax
    shr     rdx, 32
    xrstors64 [r12]

    mov     rax, [r15 + {registers_rax}]
    mov     rbx, [r15 + {registers_rbx}]
    mov     rcx, [r15 + {registers_rcx}]
    mov     rdx, [r15 + {registers_rdx}]
    mov     rdi, [r15 + {registers_rdi}]
    mov     rsi, [r15 + {registers_rsi}]
    mov     rbp, [r15 + {registers_rbp}]
    mov     r8,  [r15 + {registers_r8}]
    mov     r9,  [r15 + {registers_r9}]
    mov     r10, [r15 + {registers_r10}]
    mov     r11, [r15 + {registers_r11}]
    mov     r12, [r15 + {registers_r12}]

    test    r14, r14
    je      .Launch

    mov     r13, [r15 + {registers_r13}]
    mov     r14, [r15 + {registers_r14}]
    mov     r15, [r15 + {registers_r15}]
    vmresume
    jmp     .VmEntryFailure

.Launch:
    // return from this ffi call in vmx non-root after vmlaunch. this avoids a
    // returns-twice rust call site.
    mov     r14, {vmcs_guest_rsp}
    vmwrite r14, rsp
    jbe     .VmwriteFailure
    lea     r13, [rip + .LaunchSuccess]
    mov     r14, {vmcs_guest_rip}
    vmwrite r14, r13
    jbe     .VmwriteFailure

    mov     r13, [r15 + {registers_r13}]
    mov     r14, [r15 + {registers_r14}]
    mov     r15, [r15 + {registers_r15}]
    vmlaunch
    jmp     .VmEntryFailure

.VmwriteFailure:
    // tag vmwrite failure without touching cf/zf before capture. rust clears it.
    pushfq
    pop     rax
    bts     rax, 63
    mov     [rsp + {launch_saved_rax}], rax
    jmp     .Exit

.VmEntryFailure:
    // restore_xmm changes rsp and cf/zf. put rflags in pushaq's saved rax slot
    // so popaq returns the original vm status to rust.
    pushfq
    pop     rax
    mov     [rsp + {launch_saved_rax}], rax
    jmp     .Exit

.LaunchSuccess:
    pop     rax

    RESTORE_XMM

    POPAQ

    // zero means initial launch success. vm-entry failure returns rflags.
    xor     eax, eax
    ret

.Exit:
    pop     rax

    RESTORE_XMM

    POPAQ
    ret

.global vmexit_entry
vmexit_entry:
    push    r15
    mov     r15, [rsp + 8]
    add     r15, {vcpu_regs}
    mov     [r15 + {registers_rax}], rax
    mov     [r15 + {registers_rbx}], rbx
    mov     [r15 + {registers_rcx}], rcx
    mov     [r15 + {registers_rdx}], rdx
    mov     [r15 + {registers_rsi}], rsi
    mov     [r15 + {registers_rdi}], rdi
    mov     [r15 + {registers_rbp}], rbp
    mov     [r15 + {registers_r8}],  r8
    mov     [r15 + {registers_r9}],  r9
    mov     [r15 + {registers_r10}], r10
    mov     [r15 + {registers_r11}], r11
    mov     [r15 + {registers_r12}], r12
    mov     [r15 + {registers_r13}], r13
    mov     [r15 + {registers_r14}], r14

    mov     r14, [r15 + {vcpu_xsave_area}]
    mov     rax, [r15 + {vcpu_xsave_mask}]
    mov     rdx, rax
    shr     rdx, 32
    xsaves64 [r14]

    mov     rax, [rsp]
    mov     [r15 + {registers_r15}], rax

    sub     r15, {vcpu_regs}
    mov     rcx, r15
    sub     rsp, 0x20
    call    vmexit_handler
    int3

.global restore_guest
restore_guest:
    mov     r15, rcx

    mov     r14, rdx
    mov     rax, r8
    mov     rdx, rax
    shr     rdx, 32
    xrstors64 [r14]

    mov     rax, [r15 + {registers_rsp}]
    mov     rcx, [r15 + {registers_rip}]
    mov     rdx, [r15 + {registers_rflags}]
    mov     rsp, rax
    push    rcx
    push    rdx

    movaps  xmm0, [r15 + {registers_xmm0}]
    movaps  xmm1, [r15 + {registers_xmm1}]
    movaps  xmm2, [r15 + {registers_xmm2}]
    movaps  xmm3, [r15 + {registers_xmm3}]
    movaps  xmm4, [r15 + {registers_xmm4}]
    movaps  xmm5, [r15 + {registers_xmm5}]
    movaps  xmm6, [r15 + {registers_xmm6}]
    movaps  xmm7, [r15 + {registers_xmm7}]
    movaps  xmm8, [r15 + {registers_xmm8}]
    movaps  xmm9, [r15 + {registers_xmm9}]
    movaps  xmm10, [r15 + {registers_xmm10}]
    movaps  xmm11, [r15 + {registers_xmm11}]
    movaps  xmm12, [r15 + {registers_xmm12}]
    movaps  xmm13, [r15 + {registers_xmm13}]
    movaps  xmm14, [r15 + {registers_xmm14}]
    movaps  xmm15, [r15 + {registers_xmm15}]

    mov     rbx, [r15 + {registers_rbx}]
    mov     rdx, [r15 + {registers_rdx}]
    mov     rbp, [r15 + {registers_rbp}]
    mov     rsi, [r15 + {registers_rsi}]
    mov     rdi, [r15 + {registers_rdi}]
    mov     r8,  [r15 + {registers_r8}]
    mov     r9,  [r15 + {registers_r9}]
    mov     r10, [r15 + {registers_r10}]
    mov     r11, [r15 + {registers_r11}]
    mov     r12, [r15 + {registers_r12}]
    mov     r13, [r15 + {registers_r13}]
    mov     r14, [r15 + {registers_r14}]

    popfq
    mov     rax, [r15 + {registers_rax}]
    mov     rcx, [r15 + {registers_rcx}]
    mov     r15, [r15 + {registers_r15}]
    ret
"#,
    registers_rax = const mem::offset_of!(GuestRegs, rax),
    registers_rcx = const mem::offset_of!(GuestRegs, rcx),
    registers_rdx = const mem::offset_of!(GuestRegs, rdx),
    registers_rbx = const mem::offset_of!(GuestRegs, rbx),
    registers_rbp = const mem::offset_of!(GuestRegs, rbp),
    registers_rsi = const mem::offset_of!(GuestRegs, rsi),
    registers_rdi = const mem::offset_of!(GuestRegs, rdi),
    registers_r8  = const mem::offset_of!(GuestRegs, r8),
    registers_r9  = const mem::offset_of!(GuestRegs, r9),
    registers_r10 = const mem::offset_of!(GuestRegs, r10),
    registers_r11 = const mem::offset_of!(GuestRegs, r11),
    registers_r12 = const mem::offset_of!(GuestRegs, r12),
    registers_r13 = const mem::offset_of!(GuestRegs, r13),
    registers_r14 = const mem::offset_of!(GuestRegs, r14),
    registers_r15 = const mem::offset_of!(GuestRegs, r15),
    registers_rsp = const mem::offset_of!(GuestRegs, rsp),
    registers_rip = const mem::offset_of!(GuestRegs, rip),
    registers_rflags = const mem::offset_of!(GuestRegs, rflags),
    registers_xmm0 = const mem::offset_of!(GuestRegs, xmm0),
    registers_xmm1 = const mem::offset_of!(GuestRegs, xmm1),
    registers_xmm2 = const mem::offset_of!(GuestRegs, xmm2),
    registers_xmm3 = const mem::offset_of!(GuestRegs, xmm3),
    registers_xmm4 = const mem::offset_of!(GuestRegs, xmm4),
    registers_xmm5 = const mem::offset_of!(GuestRegs, xmm5),
    registers_xmm6 = const mem::offset_of!(GuestRegs, xmm6),
    registers_xmm7 = const mem::offset_of!(GuestRegs, xmm7),
    registers_xmm8 = const mem::offset_of!(GuestRegs, xmm8),
    registers_xmm9 = const mem::offset_of!(GuestRegs, xmm9),
    registers_xmm10 = const mem::offset_of!(GuestRegs, xmm10),
    registers_xmm11 = const mem::offset_of!(GuestRegs, xmm11),
    registers_xmm12 = const mem::offset_of!(GuestRegs, xmm12),
    registers_xmm13 = const mem::offset_of!(GuestRegs, xmm13),
    registers_xmm14 = const mem::offset_of!(GuestRegs, xmm14),
    registers_xmm15 = const mem::offset_of!(GuestRegs, xmm15),
    vcpu_regs = const mem::offset_of!(Vcpu, regs),
    vcpu_xsave_area = const mem::offset_of!(Vcpu, xsave_area),
    vcpu_xsave_mask = const mem::offset_of!(Vcpu, xsave_mask),
    vmcs_guest_rsp = const x86::vmx::vmcs::guest::RSP,
    vmcs_guest_rip = const x86::vmx::vmcs::guest::RIP,
    // skip the pointer, xmm area, and fourteen pushaq slots before saved rax.
    launch_saved_rax = const 8 + 0x100 + 14 * mem::size_of::<u64>(),
);

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(error: MonadError) -> (u8, u8, u32) {
        (
            (error.detail & 0xff) as u8,
            ((error.detail >> 8) & 0xff) as u8,
            (error.detail >> 32) as u32,
        )
    }

    #[test]
    fn vmx_status_decode() {
        let operations = [
            VmxOperation::Vmxon,
            VmxOperation::Vmxoff,
            VmxOperation::Vmclear,
            VmxOperation::Vmptrld,
            VmxOperation::Vmread,
            VmxOperation::Vmwrite,
            VmxOperation::Vmlaunch,
            VmxOperation::Vmresume,
            VmxOperation::InveptSingle,
            VmxOperation::InveptAll,
        ];
        for operation in operations {
            assert!(decode_vmx_status(operation, 0x2, None).is_ok());
            let invalid = decode_vmx_status(operation, 0x3, None)
                .expect_err("CF must decode as VMfailInvalid");
            assert_eq!(
                decoded(invalid),
                (operation as u8, VmxStatus::VmfailInvalid as u8, u32::MAX)
            );
            let valid = decode_vmx_status(operation, 0x42, Some(7))
                .expect_err("ZF must decode as VMfailValid");
            assert_eq!(
                decoded(valid),
                (operation as u8, VmxStatus::VmfailValid as u8, 7)
            );
        }
    }

    #[test]
    fn pre_vmxon_failpoint_stops_launch() {
        FAIL_BEFORE_VMXON.store(true, Ordering::Release);
        let error = pre_vmxon_failpoint().expect_err("armed failpoint must stop before VMXON");
        assert_eq!(error.code, ErrorCode::VmxInstructionFailure);
        assert!(pre_vmxon_failpoint().is_ok());
    }
}
