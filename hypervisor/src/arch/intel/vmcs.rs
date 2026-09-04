// Guest register layout follows illusion-rs
// Https://github.com/memN0ps/illusion-rs

use core::{arch::global_asm, mem};

use x86::msr::{
    IA32_FS_BASE, IA32_GS_BASE, IA32_SYSENTER_CS, IA32_SYSENTER_EIP, IA32_SYSENTER_ESP,
};
use x86::segmentation::{self, SegmentSelector};
use x86::vmx::vmcs;

use crate::{
    error::{ErrorCode, ErrorPhase, MonadError, MonadResult},
    vmm::{Vcpu, HOST_STACK_SIZE},
};

use super::{
    state::{
        lar, lsl, normalize_control_state, normalize_rflags, read_cr0, read_cr3, read_cr4,
        read_dr7, read_msr, segment_access_from_lar, Descriptors,
    },
    vmx::{vmclear, vmexit_entry, vmptrld, vmwrite},
};

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct M128A {
    pub low: u64,
    pub high: i64,
}

unsafe extern "win64" {
    pub(crate) fn capture_registers(registers: &mut GuestRegs);
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct GuestRegs {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub xmm0: M128A,
    pub xmm1: M128A,
    pub xmm2: M128A,
    pub xmm3: M128A,
    pub xmm4: M128A,
    pub xmm5: M128A,
    pub xmm6: M128A,
    pub xmm7: M128A,
    pub xmm8: M128A,
    pub xmm9: M128A,
    pub xmm10: M128A,
    pub xmm11: M128A,
    pub xmm12: M128A,
    pub xmm13: M128A,
    pub xmm14: M128A,
    pub xmm15: M128A,
}

global_asm!(
    r#"

// Rcx holds the output ptr, so the original rcx is already gone
.global capture_registers
capture_registers:
    mov     [rcx + {registers_rax}], rax
    mov     [rcx + {registers_rcx}], rcx
    mov     [rcx + {registers_rdx}], rdx
    mov     [rcx + {registers_rbx}], rbx
    mov     [rcx + {registers_rsp}], rsp
    mov     [rcx + {registers_rbp}], rbp
    mov     [rcx + {registers_rsi}], rsi
    mov     [rcx + {registers_rdi}], rdi
    mov     [rcx + {registers_r8}],  r8
    mov     [rcx + {registers_r9}],  r9
    mov     [rcx + {registers_r10}], r10
    mov     [rcx + {registers_r11}], r11
    mov     [rcx + {registers_r12}], r12
    mov     [rcx + {registers_r13}], r13
    mov     [rcx + {registers_r14}], r14
    mov     [rcx + {registers_r15}], r15

    pushfq
    pop     rax
    mov     [rcx + {registers_rflags}], rax

    // Caller rsp
    lea     rax, [rsp + 8]
    mov     [rcx + {registers_rsp}], rax

    // Caller rip
    mov     rax, [rsp]
    mov     [rcx + {registers_rip}], rax

    movaps  [rcx + {registers_xmm0}],  xmm0
    movaps  [rcx + {registers_xmm1}],  xmm1
    movaps  [rcx + {registers_xmm2}],  xmm2
    movaps  [rcx + {registers_xmm3}],  xmm3
    movaps  [rcx + {registers_xmm4}],  xmm4
    movaps  [rcx + {registers_xmm5}],  xmm5
    movaps  [rcx + {registers_xmm6}],  xmm6
    movaps  [rcx + {registers_xmm7}],  xmm7
    movaps  [rcx + {registers_xmm8}],  xmm8
    movaps  [rcx + {registers_xmm9}],  xmm9
    movaps  [rcx + {registers_xmm10}], xmm10
    movaps  [rcx + {registers_xmm11}], xmm11
    movaps  [rcx + {registers_xmm12}], xmm12
    movaps  [rcx + {registers_xmm13}], xmm13
    movaps  [rcx + {registers_xmm14}], xmm14
    movaps  [rcx + {registers_xmm15}], xmm15

    // Rax is volatile across the call.
    xor     eax, eax
    ret
"#,
    registers_rax = const mem::offset_of!(GuestRegs, rax),
    registers_rcx = const mem::offset_of!(GuestRegs, rcx),
    registers_rdx = const mem::offset_of!(GuestRegs, rdx),
    registers_rbx = const mem::offset_of!(GuestRegs, rbx),
    registers_rsp = const mem::offset_of!(GuestRegs, rsp),
    registers_rbp = const mem::offset_of!(GuestRegs, rbp),
    registers_rsi = const mem::offset_of!(GuestRegs, rsi),
    registers_rdi = const mem::offset_of!(GuestRegs, rdi),
    registers_r8 = const mem::offset_of!(GuestRegs, r8),
    registers_r9 = const mem::offset_of!(GuestRegs, r9),
    registers_r10 = const mem::offset_of!(GuestRegs, r10),
    registers_r11 = const mem::offset_of!(GuestRegs, r11),
    registers_r12 = const mem::offset_of!(GuestRegs, r12),
    registers_r13 = const mem::offset_of!(GuestRegs, r13),
    registers_r14 = const mem::offset_of!(GuestRegs, r14),
    registers_r15 = const mem::offset_of!(GuestRegs, r15),
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
);

#[inline]
fn vmcs_access_rights(selector: SegmentSelector) -> u64 {
    u64::from(segment_access_from_lar(selector.bits(), lar(selector)))
}

#[inline]
fn host_selector(selector: SegmentSelector) -> u64 {
    u64::from(selector.bits() & !0x7)
}
fn setup_guest_state(guest_desc: &Descriptors, regs: &GuestRegs, vcpu: &Vcpu) -> MonadResult<()> {
    let (cs, ss, ds, es, fs, gs) = (
        segmentation::cs(),
        segmentation::ss(),
        segmentation::ds(),
        segmentation::es(),
        segmentation::fs(),
        segmentation::gs(),
    );
    let requested_cr0 = vcpu.original_controls.cr0;
    let normalized_cr0 =
        (requested_cr0 | vcpu.capabilities.cr0_fixed0) & vcpu.capabilities.cr0_fixed1;
    let cr0 = normalize_control_state(
        requested_cr0,
        vcpu.capabilities.cr0_fixed0,
        vcpu.capabilities.cr0_fixed1,
        requested_cr0 ^ normalized_cr0,
        requested_cr0,
    )?;
    let requested_cr4 = vcpu.original_controls.cr4;
    let normalized_cr4 =
        (requested_cr4 | vcpu.capabilities.cr4_fixed0) & vcpu.capabilities.cr4_fixed1;
    let cr4 = normalize_control_state(
        requested_cr4,
        vcpu.capabilities.cr4_fixed0,
        vcpu.capabilities.cr4_fixed1,
        requested_cr4 ^ normalized_cr4,
        requested_cr4,
    )?;

    vmwrite(vmcs::guest::CR0, cr0.guest)?;
    vmwrite(vmcs::guest::CR3, read_cr3())?;
    vmwrite(vmcs::guest::CR4, cr4.guest)?;
    vmwrite(vmcs::guest::DR7, read_dr7())?;

    vmwrite(vmcs::guest::RSP, regs.rsp)?;
    vmwrite(vmcs::guest::RIP, regs.rip)?;
    vmwrite(vmcs::guest::RFLAGS, normalize_rflags(regs.rflags))?;

    vmwrite(vmcs::guest::CS_SELECTOR, u64::from(cs.bits()))?;
    vmwrite(vmcs::guest::SS_SELECTOR, u64::from(ss.bits()))?;
    vmwrite(vmcs::guest::DS_SELECTOR, u64::from(ds.bits()))?;
    vmwrite(vmcs::guest::ES_SELECTOR, u64::from(es.bits()))?;
    vmwrite(vmcs::guest::FS_SELECTOR, u64::from(fs.bits()))?;
    vmwrite(vmcs::guest::GS_SELECTOR, u64::from(gs.bits()))?;
    vmwrite(vmcs::guest::LDTR_SELECTOR, 0u64)?;
    vmwrite(vmcs::guest::TR_SELECTOR, u64::from(guest_desc.tr.bits()))?;

    vmwrite(vmcs::guest::CS_BASE, 0u64)?;
    vmwrite(vmcs::guest::SS_BASE, 0u64)?;
    vmwrite(vmcs::guest::DS_BASE, 0u64)?;
    vmwrite(vmcs::guest::ES_BASE, 0u64)?;

    // Long mode
    vmwrite(vmcs::guest::FS_BASE, read_msr(IA32_FS_BASE))?;
    vmwrite(vmcs::guest::GS_BASE, read_msr(IA32_GS_BASE))?;
    vmwrite(vmcs::guest::IA32_SYSENTER_CS, read_msr(IA32_SYSENTER_CS))?;
    vmwrite(vmcs::guest::IA32_SYSENTER_ESP, read_msr(IA32_SYSENTER_ESP))?;
    vmwrite(vmcs::guest::IA32_SYSENTER_EIP, read_msr(IA32_SYSENTER_EIP))?;

    vmwrite(vmcs::guest::LDTR_BASE, 0u64)?;
    vmwrite(vmcs::guest::TR_BASE, guest_desc.tss_base)?;

    vmwrite(vmcs::guest::CS_LIMIT, u64::from(lsl(cs).unwrap_or(0)))?;
    vmwrite(vmcs::guest::SS_LIMIT, u64::from(lsl(ss).unwrap_or(0)))?;
    vmwrite(vmcs::guest::DS_LIMIT, u64::from(lsl(ds).unwrap_or(0)))?;
    vmwrite(vmcs::guest::ES_LIMIT, u64::from(lsl(es).unwrap_or(0)))?;
    vmwrite(vmcs::guest::FS_LIMIT, u64::from(lsl(fs).unwrap_or(0)))?;
    vmwrite(vmcs::guest::GS_LIMIT, u64::from(lsl(gs).unwrap_or(0)))?;
    vmwrite(vmcs::guest::LDTR_LIMIT, 0u64)?;
    vmwrite(vmcs::guest::TR_LIMIT, u64::from(guest_desc.tss_limit))?;

    vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, vmcs_access_rights(cs))?;
    vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, vmcs_access_rights(ss))?;
    vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, vmcs_access_rights(ds))?;
    vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, vmcs_access_rights(es))?;
    vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, vmcs_access_rights(fs))?;
    vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, vmcs_access_rights(gs))?;
    vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, 1u64 << 16)?;
    vmwrite(
        vmcs::guest::TR_ACCESS_RIGHTS,
        vmcs_access_rights(guest_desc.tr),
    )?;

    vmwrite(vmcs::guest::GDTR_BASE, guest_desc.gdtr.base as u64)?;
    vmwrite(vmcs::guest::IDTR_BASE, guest_desc.idtr.base as u64)?;
    vmwrite(vmcs::guest::GDTR_LIMIT, u64::from(guest_desc.gdtr.limit))?;
    vmwrite(vmcs::guest::IDTR_LIMIT, u64::from(guest_desc.idtr.limit))?;

    // No shadow VMCS is linked.
    vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX)?;
    Ok(())
}

fn setup_host_state(
    host_desc: &Descriptors,
    host_cr3: u64,
    host_rsp: u64,
    host_rip: u64,
) -> MonadResult<()> {
    vmwrite(vmcs::host::CR0, read_cr0())?;
    vmwrite(vmcs::host::CR3, host_cr3)?;
    vmwrite(vmcs::host::CR4, read_cr4())?;

    vmwrite(vmcs::host::CS_SELECTOR, host_selector(segmentation::cs()))?;
    vmwrite(vmcs::host::SS_SELECTOR, host_selector(segmentation::ss()))?;
    vmwrite(vmcs::host::DS_SELECTOR, host_selector(segmentation::ds()))?;
    vmwrite(vmcs::host::ES_SELECTOR, host_selector(segmentation::es()))?;
    vmwrite(vmcs::host::FS_SELECTOR, host_selector(segmentation::fs()))?;
    vmwrite(vmcs::host::GS_SELECTOR, host_selector(segmentation::gs()))?;
    vmwrite(vmcs::host::TR_SELECTOR, host_selector(host_desc.tr))?;

    vmwrite(vmcs::host::FS_BASE, read_msr(IA32_FS_BASE))?;
    vmwrite(vmcs::host::GS_BASE, read_msr(IA32_GS_BASE))?;
    vmwrite(vmcs::host::IA32_SYSENTER_CS, read_msr(IA32_SYSENTER_CS))?;
    vmwrite(vmcs::host::IA32_SYSENTER_ESP, read_msr(IA32_SYSENTER_ESP))?;
    vmwrite(vmcs::host::IA32_SYSENTER_EIP, read_msr(IA32_SYSENTER_EIP))?;
    vmwrite(vmcs::host::TR_BASE, host_desc.tss_base)?;
    vmwrite(vmcs::host::GDTR_BASE, host_desc.gdtr.base as u64)?;
    vmwrite(vmcs::host::IDTR_BASE, host_desc.idtr.base as u64)?;

    vmwrite(vmcs::host::RSP, host_rsp)?;
    vmwrite(vmcs::host::RIP, host_rip)?;

    Ok(())
}

unsafe fn setup_controls(vcpu: &mut Vcpu) -> MonadResult<()> {
    if vcpu.active_view.eptp == 0 {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::InvalidLifecycleState,
            0,
        ));
    }

    let controls = vcpu.capabilities.controls;
    let requested_cr0 = vcpu.original_controls.cr0;
    let normalized_cr0 =
        (requested_cr0 | vcpu.capabilities.cr0_fixed0) & vcpu.capabilities.cr0_fixed1;
    let cr0 = normalize_control_state(
        requested_cr0,
        vcpu.capabilities.cr0_fixed0,
        vcpu.capabilities.cr0_fixed1,
        requested_cr0 ^ normalized_cr0,
        requested_cr0,
    )?;
    let requested_cr4 = vcpu.original_controls.cr4;
    let normalized_cr4 =
        (requested_cr4 | vcpu.capabilities.cr4_fixed0) & vcpu.capabilities.cr4_fixed1;
    let cr4 = normalize_control_state(
        requested_cr4,
        vcpu.capabilities.cr4_fixed0,
        vcpu.capabilities.cr4_fixed1,
        requested_cr4 ^ normalized_cr4,
        requested_cr4,
    )?;

    vmwrite(
        vmcs::control::PINBASED_EXEC_CONTROLS,
        u64::from(controls.pinbased),
    )?;
    vmwrite(
        vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
        u64::from(controls.primary),
    )?;
    vmwrite(
        vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
        u64::from(controls.secondary),
    )?;
    vmwrite(vmcs::control::VMENTRY_CONTROLS, u64::from(controls.vmentry))?;
    vmwrite(vmcs::control::VMEXIT_CONTROLS, u64::from(controls.vmexit))?;
    vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, vcpu.msr_bitmap_pa)?;
    // Eptp cache type is for the tables, not mapped ram
    vmwrite(vmcs::control::EPTP_FULL, vcpu.active_view.eptp)?;

    vmwrite(vmcs::control::CR0_GUEST_HOST_MASK, cr0.mask)?;
    vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, cr4.mask)?;
    vmwrite(vmcs::control::CR0_READ_SHADOW, cr0.read_shadow)?;
    vmwrite(vmcs::control::CR4_READ_SHADOW, cr4.read_shadow)?;

    vmwrite(vmcs::control::EXCEPTION_BITMAP, 0u64)?;
    vmwrite(vmcs::control::PAGE_FAULT_ERR_CODE_MASK, 0u64)?;
    vmwrite(vmcs::control::PAGE_FAULT_ERR_CODE_MATCH, 0u64)?;
    vmwrite(vmcs::control::CR3_TARGET_COUNT, 0u64)?;
    vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, 0u64)?;
    vmwrite(vmcs::control::VMENTRY_MSR_LOAD_COUNT, 0u64)?;
    vmwrite(vmcs::control::VMEXIT_MSR_STORE_COUNT, 0u64)?;
    vmwrite(vmcs::control::VMEXIT_MSR_LOAD_COUNT, 0u64)?;

    Ok(())
}

/// Fills the current processor's VMCS from checked vCPU state.
///
/// # Safety
///
/// `vcpu` uniquely belongs to the pinned processor. Its VMCS, stack, bitmap,
/// EPT, descriptors, and capability snapshot stay valid until VMXOFF.
pub unsafe fn setup_vmcs(vcpu: *mut Vcpu) -> MonadResult<()> {
    if vcpu.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::InvalidLifecycleState,
            0,
        ));
    }

    let vcpu_ptr = vcpu;
    let vcpu = unsafe { &mut *vcpu };

    unsafe {
        vmclear(vcpu.vmcs_pa)?;
        vmptrld(vcpu.vmcs_pa)?;

        setup_guest_state(&vcpu.guest_desc, &vcpu.regs, vcpu)?;

        let host_top = vcpu.host_stack.add(HOST_STACK_SIZE) as usize & !0xf;
        let host_rsp = host_top - mem::size_of::<*mut Vcpu>();
        *(host_rsp as *mut *mut Vcpu) = vcpu_ptr;
        setup_host_state(
            &vcpu.host_desc,
            read_cr3(),
            host_rsp as u64,
            vmexit_entry as *const () as usize as u64,
        )?;

        setup_controls(vcpu)
    }
}
