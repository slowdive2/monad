use core::arch::asm;

use x86::{
    bits64::rflags::RFlags,
    dtables::{sgdt, sidt, DescriptorTablePointer},
    segmentation::SegmentSelector,
};

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

pub fn read_tsc() -> u64 {
    // safety: rdtsc has no memory operand and is available on x86-64.
    unsafe { core::arch::x86_64::_rdtsc() }
}

const RFLAGS_FIXED_ONE: u64 = 1 << 1;
const RFLAGS_VM: u64 = 1 << 17;
const RFLAGS_IOPL: u64 = 3 << 12;
const RFLAGS_ARCHITECTURAL_MASK: u64 = 0x003f_7fd7;
const SEGMENT_UNUSABLE: u32 = 1 << 16;

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateErrorDetail {
    DescriptorOutOfBounds = 1,
    DescriptorAddressOverflow = 2,
    InvalidFixedMasks = 3,
    InvalidReadShadow = 4,
    InvalidTaskRegister = 5,
}

fn state_error(code: ErrorCode, detail: StateErrorDetail) -> MonadError {
    MonadError::new(ErrorPhase::Launch, code, detail as u64)
}

pub struct Descriptors {
    pub gdtr: DescriptorTablePointer<u64>,
    pub idtr: DescriptorTablePointer<u64>,
    pub tr: SegmentSelector,
    pub tss_base: u64,
    pub tss_limit: u32,
    pub tss_access_rights: u32,
}

impl Descriptors {
    /// captures descriptor state for the current processor.
    ///
    /// # Safety
    ///
    /// the caller stays at cpl0 on one processor. the active gdt stays readable.
    pub unsafe fn capture_current() -> MonadResult<Self> {
        let mut gdtr = DescriptorTablePointer::default();
        let mut idtr = DescriptorTablePointer::default();
        // safety: the caller guarantees cpl 0 and processor stability; both output
        // pointers refer to initialized writable stack storage.
        unsafe {
            sgdt(&mut gdtr);
            sidt(&mut idtr);
        }

        // safety: the caller guarantees cpl 0 and processor stability.
        let tr = unsafe { read_tr() };
        // safety: the captured gdt stays readable; bounds are
        // validated before either descriptor slot is dereferenced.
        let (tss_base, tss_limit, tss_access_rights) =
            unsafe { read_tss_checked(gdtr.base, gdtr.limit, tr)? };

        Ok(Self {
            gdtr,
            idtr,
            tr,
            tss_base,
            tss_limit,
            tss_access_rights,
        })
    }
}

unsafe fn read_tr() -> SegmentSelector {
    let selector: u16;
    // safety: str is available at cpl 0 and only writes the selected register.
    unsafe {
        asm!(
            "str {selector:x}",
            selector = out(reg) selector,
            options(nomem, nostack, preserves_flags)
        );
    }
    SegmentSelector::from_raw(selector)
}

fn descriptor_slot_range(selector: u16, table_limit: u16, slots: u16) -> MonadResult<usize> {
    let offset = usize::from(selector & !0x7);
    let byte_count = usize::from(slots)
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| {
            state_error(
                ErrorCode::InvalidDescriptor,
                StateErrorDetail::DescriptorAddressOverflow,
            )
        })?;
    let final_byte = offset.checked_add(byte_count - 1).ok_or_else(|| {
        state_error(
            ErrorCode::InvalidDescriptor,
            StateErrorDetail::DescriptorAddressOverflow,
        )
    })?;
    if final_byte > usize::from(table_limit) {
        return Err(state_error(
            ErrorCode::InvalidDescriptor,
            StateErrorDetail::DescriptorOutOfBounds,
        ));
    }
    Ok(offset / core::mem::size_of::<u64>())
}

fn decode_tss_slots(low: u64, high: u64) -> (u64, u32, u32) {
    let base_low = ((low >> 16) & 0xff_ffff) | (((low >> 56) & 0xff) << 24);
    let base = base_low | ((high & 0xffff_ffff) << 32);
    let raw_limit = (low as u32 & 0xffff) | (((low >> 48) as u32 & 0xf) << 16);
    let limit = if low & (1 << 55) != 0 {
        (raw_limit << 12) | 0xfff
    } else {
        raw_limit
    };
    let access_rights = ((low >> 40) as u32 & 0xff) | ((low >> 40) as u32 & 0xf000);
    (base, limit, access_rights)
}

unsafe fn read_tss_checked(
    gdt_base: *const u64,
    gdt_limit: u16,
    tr: SegmentSelector,
) -> MonadResult<(u64, u32, u32)> {
    if tr.bits() & 0x4 != 0 || tr.bits() & !0x7 == 0 {
        return Err(state_error(
            ErrorCode::InvalidDescriptor,
            StateErrorDetail::InvalidTaskRegister,
        ));
    }
    let index = descriptor_slot_range(tr.bits(), gdt_limit, 2)?;
    let byte_offset = index
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or_else(|| {
            state_error(
                ErrorCode::InvalidDescriptor,
                StateErrorDetail::DescriptorAddressOverflow,
            )
        })?;
    let low_address = (gdt_base as usize)
        .checked_add(byte_offset)
        .ok_or_else(|| {
            state_error(
                ErrorCode::InvalidDescriptor,
                StateErrorDetail::DescriptorAddressOverflow,
            )
        })?;
    let high_address = low_address
        .checked_add(core::mem::size_of::<u64>())
        .ok_or_else(|| {
            state_error(
                ErrorCode::InvalidDescriptor,
                StateErrorDetail::DescriptorAddressOverflow,
            )
        })?;
    // safety: both full slots are inside the readable captured gdt.
    let (low, high) = unsafe {
        (
            (low_address as *const u64).read_unaligned(),
            (high_address as *const u64).read_unaligned(),
        )
    };
    let descriptor_type = (low >> 40) & 0xf;
    let system = low & (1 << 44) == 0;
    let present = low & (1 << 47) != 0;
    if !system || !present || !matches!(descriptor_type, 9 | 11) {
        return Err(state_error(
            ErrorCode::InvalidDescriptor,
            StateErrorDetail::InvalidTaskRegister,
        ));
    }
    Ok(decode_tss_slots(low, high))
}

pub fn segment_access_from_lar(selector: u16, lar_result: Option<u32>) -> u32 {
    if selector & !0x3 == 0 || lar_result.is_none() {
        return SEGMENT_UNUSABLE;
    }
    // lar defines only the access byte and avl/l/db/g nibble used by the vmcs.
    // the mask keeps undefined destination bits from becoming
    // reserved-one guest-state bits.
    (lar_result.unwrap_or(0) >> 8) & 0xf0ff
}

pub(crate) fn lar(selector: SegmentSelector) -> Option<u32> {
    let access_rights: u64;
    let flags: u64;
    // safety: lar is valid here; zf reports an inaccessible selector.
    unsafe {
        asm!(
            "lar {access_rights}, {selector}",
            "pushfq",
            "pop {flags}",
            access_rights = lateout(reg) access_rights,
            selector = in(reg) u64::from(selector.bits()),
            flags = lateout(reg) flags,
        );
    }
    RFlags::from_raw(flags)
        .contains(RFlags::FLAGS_ZF)
        .then_some(access_rights as u32)
}

pub(crate) fn lsl(selector: SegmentSelector) -> Option<u32> {
    let limit: u64;
    let flags: u64;
    // safety: lsl is valid here; zf reports an inaccessible selector.
    unsafe {
        asm!(
            "lsl {limit}, {selector}",
            "pushfq",
            "pop {flags}",
            limit = lateout(reg) limit,
            selector = in(reg) u64::from(selector.bits()),
            flags = lateout(reg) flags,
        );
    }
    RFlags::from_raw(flags)
        .contains(RFlags::FLAGS_ZF)
        .then_some(limit as u32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizedControlState {
    pub guest: u64,
    pub mask: u64,
    pub read_shadow: u64,
}

pub fn normalize_rflags(input: u64) -> u64 {
    ((input & RFLAGS_ARCHITECTURAL_MASK) & !(RFLAGS_VM | RFLAGS_IOPL)) | RFLAGS_FIXED_ONE
}

pub fn normalize_control_state(
    requested: u64,
    fixed0: u64,
    fixed1: u64,
    mask: u64,
    read_shadow: u64,
) -> MonadResult<NormalizedControlState> {
    if fixed0 & !fixed1 != 0 {
        return Err(state_error(
            ErrorCode::InvalidGuestState,
            StateErrorDetail::InvalidFixedMasks,
        ));
    }
    let normalized = (requested | fixed0) & fixed1;
    let forced = requested ^ normalized;
    if forced & !mask != 0 {
        return Err(state_error(
            ErrorCode::InvalidGuestState,
            StateErrorDetail::InvalidReadShadow,
        ));
    }
    if (read_shadow ^ requested) & mask != 0 {
        return Err(state_error(
            ErrorCode::InvalidGuestState,
            StateErrorDetail::InvalidReadShadow,
        ));
    }
    Ok(NormalizedControlState {
        guest: normalized,
        mask,
        read_shadow,
    })
}

pub(crate) fn read_msr(msr: u32) -> u64 {
    // safety: capability checks cover the msr and the caller runs at cpl 0.
    unsafe { x86::msr::rdmsr(msr) }
}

pub(crate) fn write_msr(msr: u32, value: u64) {
    // safety: the caller selects a writable msr and runs at cpl 0.
    unsafe { x86::msr::wrmsr(msr, value) };
}

pub(crate) fn read_cr0() -> u64 {
    let value: u64;
    // safety: kernel-only architectural capture; never truncate unknown bits.
    unsafe {
        asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

pub(crate) fn write_cr0(value: u64) {
    // safety: caller validates the complete raw architectural value.
    unsafe {
        asm!("mov cr0, {}", in(reg) value, options(nostack, preserves_flags));
    }
}

/// Capture the system process's kernel root while briefly attached at PASSIVE_LEVEL.
pub(crate) fn system_cr3() -> MonadResult<u64> {
    use wdk_sys::{
        ntddk::{KeGetCurrentIrql, KeStackAttachProcess, KeUnstackDetachProcess},
        KAPC_STATE, PEPROCESS,
    };
    if unsafe { KeGetCurrentIrql() } != 0 {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::InvalidLifecycleState,
            0,
        ));
    }
    // COFF data imports have no function thunk. Bind the IAT slot explicitly;
    // the generated wdk-sys declaration omits dllimport for this exported variable.
    unsafe extern "system" {
        #[link_name = "__imp_PsInitialSystemProcess"]
        static SYSTEM_PROCESS_IMPORT: *const PEPROCESS;
    }
    let process = unsafe { *SYSTEM_PROCESS_IMPORT };
    if process.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::InvalidGuestState,
            0,
        ));
    }
    let mut apc = unsafe { core::mem::zeroed::<KAPC_STATE>() };
    // No allocation, I/O or fallible operation occurs while attached.
    unsafe {
        KeStackAttachProcess(process.cast(), &mut apc);
    }
    let root = read_cr3() & !0xfff;
    unsafe {
        KeUnstackDetachProcess(&mut apc);
    }
    if root == 0 {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::InvalidGuestState,
            0,
        ));
    }
    Ok(root)
}

pub(crate) fn read_cr3() -> u64 {
    // safety: monad calls this only from cpl0 kernel context.
    unsafe { x86::controlregs::cr3() }
}

pub(crate) fn write_cr3(value: u64) {
    // safety: this is a captured active cr3.
    unsafe { x86::controlregs::cr3_write(value) };
}

pub(crate) fn read_cr4() -> u64 {
    let value: u64;
    // safety: kernel-only architectural capture; never truncate unknown bits.
    unsafe {
        asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

pub(crate) fn write_cr4(value: u64) {
    // safety: caller validates the complete raw architectural value.
    unsafe {
        asm!("mov cr4, {}", in(reg) value, options(nostack, preserves_flags));
    }
}

pub(crate) fn restore_native_xcr0(value: u64) {
    // safety: this is the captured pre-launch XCR0 on the same CPU.
    unsafe {
        core::arch::x86_64::_xsetbv(0, value);
    }
}

pub(crate) fn read_dr7() -> u64 {
    // safety: monad calls this only from cpl0 kernel context.
    unsafe { x86::debugregs::dr7().0 as u64 }
}

pub(crate) fn write_dr7(value: u64) {
    // safety: this value came from captured guest state.
    unsafe { x86::debugregs::dr7_write(x86::debugregs::Dr7(value as usize)) };
}

/// captures the debug registers that are not switched by the vmcs.
///
/// # Safety
///
/// the caller runs at cpl0 on the processor whose state it owns.
pub unsafe fn read_debug_state() -> crate::lifecycle::DebugState {
    let (dr0, dr1, dr2, dr3, dr6): (u64, u64, u64, u64, u64);
    // safety: the caller owns this processor's privileged register state.
    unsafe {
        asm!("mov {}, dr0", out(reg) dr0, options(nostack, preserves_flags));
        asm!("mov {}, dr1", out(reg) dr1, options(nostack, preserves_flags));
        asm!("mov {}, dr2", out(reg) dr2, options(nostack, preserves_flags));
        asm!("mov {}, dr3", out(reg) dr3, options(nostack, preserves_flags));
        asm!("mov {}, dr6", out(reg) dr6, options(nostack, preserves_flags));
    }
    crate::lifecycle::DebugState {
        dr0,
        dr1,
        dr2,
        dr3,
        dr6,
        dr7: read_dr7(),
    }
}

/// restores the complete captured debug-register set.
///
/// # Safety
///
/// the caller runs at cpl0 on the processor that produced `state`.
pub unsafe fn write_debug_state(state: crate::lifecycle::DebugState) {
    // safety: the values came from this processor's captured state.
    unsafe {
        asm!("mov dr0, {}", in(reg) state.dr0, options(nostack, preserves_flags));
        asm!("mov dr1, {}", in(reg) state.dr1, options(nostack, preserves_flags));
        asm!("mov dr2, {}", in(reg) state.dr2, options(nostack, preserves_flags));
        asm!("mov dr3, {}", in(reg) state.dr3, options(nostack, preserves_flags));
        asm!("mov dr6, {}", in(reg) state.dr6, options(nostack, preserves_flags));
    }
    write_dr7(state.dr7);
}

/// State loaded implicitly by VM exit that native return must reconstruct.
/// CR2, DR0-3/6, KERNEL_GS_BASE, PAT and EFER remain live and are not modified by root.
pub(crate) struct NativeReturnState {
    gdtr: DescriptorTablePointer<u64>,
    idtr: DescriptorTablePointer<u64>,
    selectors: [u16; 4],
    fs_base: u64,
    gs_base: u64,
    debugctl: u64,
}

impl NativeReturnState {
    pub(crate) fn capture(mut read: impl FnMut(u32) -> MonadResult<u64>) -> MonadResult<Self> {
        use x86::vmx::vmcs::{guest as g, host as h};
        // Keep the controlled Windows CPL0/TSS return profile; no busy-TSS rewriting.
        if read(g::CS_SELECTOR)? != read(h::CS_SELECTOR)?
            || read(g::SS_SELECTOR)? != read(h::SS_SELECTOR)?
            || read(g::TR_SELECTOR)? != read(h::TR_SELECTOR)?
            || read(g::TR_BASE)? != read(h::TR_BASE)?
            || read(g::TR_LIMIT)? != 0x67
            || read(g::LDTR_SELECTOR)? != 0
        {
            return Err(MonadError::new(
                ErrorPhase::Shutdown,
                ErrorCode::InvalidGuestState,
                0,
            ));
        }
        Ok(Self {
            gdtr: DescriptorTablePointer {
                limit: read(g::GDTR_LIMIT)? as u16,
                base: read(g::GDTR_BASE)? as *const u64,
            },
            idtr: DescriptorTablePointer {
                limit: read(g::IDTR_LIMIT)? as u16,
                base: read(g::IDTR_BASE)? as *const u64,
            },
            selectors: [
                read(g::DS_SELECTOR)? as u16,
                read(g::ES_SELECTOR)? as u16,
                read(g::FS_SELECTOR)? as u16,
                read(g::GS_SELECTOR)? as u16,
            ],
            fs_base: read(g::FS_BASE)?,
            gs_base: read(g::GS_BASE)?,
            debugctl: read(g::IA32_DEBUGCTL_FULL)?,
        })
    }

    /// # Safety
    /// VMX is off on the captured CPU; guest CR3 and the CPL0 return profile are active.
    pub(crate) unsafe fn restore(&self) {
        unsafe {
            x86::dtables::lgdt(&self.gdtr);
            x86::dtables::lidt(&self.idtr);
            asm!("mov ds, {ds:x}", "mov es, {es:x}", "mov fs, {fs:x}", "mov gs, {gs:x}",
                ds=in(reg) self.selectors[0], es=in(reg) self.selectors[1],
                fs=in(reg) self.selectors[2], gs=in(reg) self.selectors[3],
                options(nostack, preserves_flags));
        }
        write_msr(x86::msr::IA32_FS_BASE, self.fs_base);
        write_msr(x86::msr::IA32_GS_BASE, self.gs_base);
        write_msr(0x1d9, self.debugctl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_bounds_and_unusable_segments() {
        assert_eq!(descriptor_slot_range(8, 23, 2), Ok(1));
        assert_eq!(
            descriptor_slot_range(8, 15, 2).map_err(|error| error.code),
            Err(ErrorCode::InvalidDescriptor)
        );
        assert_eq!(
            descriptor_slot_range(16, 15, 1).map_err(|error| error.code),
            Err(ErrorCode::InvalidDescriptor)
        );
        let table = [0, (9u64 << 40) | (1u64 << 47) | 0x1234, 0];
        let tr = SegmentSelector::from_raw(8);
        let decoded = unsafe { read_tss_checked(table.as_ptr(), 23, tr) }
            .expect("last complete two-slot TSS must decode");
        assert_eq!(decoded.1, 0x1234);
        assert_eq!(
            unsafe { read_tss_checked(table.as_ptr(), 15, tr) }.map_err(|error| error.code),
            Err(ErrorCode::InvalidDescriptor)
        );
        assert_eq!(segment_access_from_lar(0x10, None), SEGMENT_UNUSABLE);
        assert_eq!(segment_access_from_lar(0, Some(0xffff)), SEGMENT_UNUSABLE);
        assert_eq!(segment_access_from_lar(0x10, Some(0x00cf_9300)), 0xc093);
        assert_eq!(segment_access_from_lar(0x10, Some(0xffcf_9300)), 0xc093);
    }

    #[test]
    fn guest_state_normalization() {
        let rflags = normalize_rflags(u64::MAX);
        assert_ne!(rflags & RFLAGS_FIXED_ONE, 0);
        assert_eq!(rflags & RFLAGS_VM, 0);
        assert_eq!(rflags & RFLAGS_IOPL, 0);
        assert_eq!(rflags & !RFLAGS_ARCHITECTURAL_MASK, 0);
        assert_ne!(normalize_rflags(1 << 16) & (1 << 16), 0);

        let state =
            normalize_control_state(0x20, 1, 0xff, 0x21, 0x20).expect("consistent control state");
        assert_eq!(state.guest, 0x21);
        assert_eq!(
            normalize_control_state(0, 2, 1, 0, 0).map_err(|error| error.code),
            Err(ErrorCode::InvalidGuestState)
        );
        assert_eq!(
            normalize_control_state(0x20, 0, u64::MAX, 0x20, 0).map_err(|error| error.code),
            Err(ErrorCode::InvalidGuestState)
        );
        assert_eq!(
            normalize_control_state(0, 1, u64::MAX, 0, 0).map_err(|error| error.code),
            Err(ErrorCode::InvalidGuestState)
        );
    }
    #[test]
    fn native_return_reads_current_descriptor_and_base_state() {
        use x86::vmx::vmcs::{guest as g, host as h};
        let read = |field| {
            Ok(match field {
                g::CS_SELECTOR | h::CS_SELECTOR => 0x10,
                g::SS_SELECTOR | h::SS_SELECTOR => 0x18,
                g::TR_SELECTOR | h::TR_SELECTOR => 0x40,
                g::TR_BASE | h::TR_BASE => 0x9000,
                g::TR_LIMIT => 0x67,
                g::GDTR_LIMIT => 0x77,
                g::IDTR_LIMIT => 0xfff,
                g::GDTR_BASE => 0x1000,
                g::IDTR_BASE => 0x2000,
                g::FS_BASE => 0x3000,
                g::GS_BASE => 0x4000,
                g::IA32_DEBUGCTL_FULL => 0x5,
                _ => 0,
            })
        };
        let state = NativeReturnState::capture(read).expect("current state");
        let (gdt_limit, idt_limit) = (state.gdtr.limit, state.idtr.limit);
        assert_eq!((gdt_limit, idt_limit), (0x77, 0xfff));
        assert_eq!(
            (state.fs_base, state.gs_base, state.debugctl),
            (0x3000, 0x4000, 5)
        );
        for unsupported in [g::CS_SELECTOR, g::TR_BASE, g::TR_LIMIT, g::LDTR_SELECTOR] {
            assert!(NativeReturnState::capture(|field| {
                if field == unsupported {
                    Ok(0xdead)
                } else {
                    read(field)
                }
            })
            .is_err());
        }
    }
}
