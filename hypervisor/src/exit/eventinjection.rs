use bit_field::BitField;

use crate::arch::intel::vmx::{vmread, vmwrite};
use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};
use crate::exit::context::ExitContext;
use crate::vmm::Vcpu;
use x86::vmx::vmcs;

use super::disposition::ExitDisposition;

const RFLAGS_RF_BIT: usize = 16;
const VECTOR_INVALID_OPCODE: u8 = 6;
const VECTOR_GENERAL_PROTECTION: u8 = 13;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptionType {
    ExternalInterrupt = 0,
    Reserved = 1,
    Nmi = 2,
    HardwareException = 3,
    SoftwareInterrupt = 4,
    PrivilegedSoftwareException = 5,
    SoftwareException = 6,
    OtherEvent = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmEntryEvent {
    pub vector: u8,
    pub interruption_type: InterruptionType,
    pub error_code: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InjectionUpdate {
    pub interruption_info: u32,
    pub error_code: Option<u32>,
    pub instruction_length: u32,
    pub guest_rflags: u64,
}

const VALID_BIT: u32 = 1 << 31;
const DELIVER_ERROR_CODE_BIT: u32 = 1 << 11;
const TYPE_SHIFT: u32 = 8;
const TYPE_MASK: u32 = 0x7;

fn vectoring_instruction_length(
    interruption_info: u32,
    exit_instruction_length: Option<u32>,
) -> MonadResult<u32> {
    match (interruption_info >> TYPE_SHIFT) & TYPE_MASK {
        value
            if value == InterruptionType::SoftwareInterrupt as u32
                || value == InterruptionType::PrivilegedSoftwareException as u32
                || value == InterruptionType::SoftwareException as u32 =>
        {
            exit_instruction_length.ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::ExitHandling,
                    ErrorCode::InvalidGuestState,
                    u64::from(interruption_info),
                )
            })
        }
        _ => Ok(0),
    }
}

/// Converts a valid VM-exit IDT-vectoring event into a VM-entry event without
/// changing its vector, type, or error code. The architecture specifies this
/// copy for completing an event whose delivery caused a VM exit.
pub fn prepare_reinjection(
    context: &ExitContext,
    pending_entry_info: u32,
) -> MonadResult<Option<InjectionUpdate>> {
    let Some(vectoring_info) = context.idt_vectoring_info else {
        return Ok(None);
    };
    if vectoring_info & VALID_BIT == 0 {
        return Ok(None);
    }
    if pending_entry_info & VALID_BIT != 0 {
        return Err(MonadError::new(
            ErrorPhase::ExitHandling,
            ErrorCode::WrongObjectState,
            u64::from(pending_entry_info),
        ));
    }
    if ((vectoring_info >> TYPE_SHIFT) & TYPE_MASK) == InterruptionType::Reserved as u32 {
        return Err(MonadError::new(
            ErrorPhase::ExitHandling,
            ErrorCode::InvalidGuestState,
            u64::from(vectoring_info),
        ));
    }

    let error_code = if vectoring_info & DELIVER_ERROR_CODE_BIT != 0 {
        Some(context.idt_vectoring_error_code.ok_or_else(|| {
            MonadError::new(
                ErrorPhase::ExitHandling,
                ErrorCode::InvalidGuestState,
                u64::from(vectoring_info),
            )
        })?)
    } else {
        None
    };

    Ok(Some(InjectionUpdate {
        interruption_info: vectoring_info,
        error_code,
        instruction_length: vectoring_instruction_length(
            vectoring_info,
            context.instruction_length,
        )?,
        guest_rflags: context.guest_rflags,
    }))
}

pub fn prepare_injection(
    context: &ExitContext,
    event: VmEntryEvent,
    pending_entry_info: u32,
) -> MonadResult<InjectionUpdate> {
    if pending_entry_info & (1 << 31) != 0
        || context
            .idt_vectoring_info
            .is_some_and(|info| info & (1 << 31) != 0)
    {
        return Err(MonadError::new(
            ErrorPhase::ExitHandling,
            ErrorCode::WrongObjectState,
            u64::from(pending_entry_info),
        ));
    }
    let mut rflags = context.guest_rflags;
    rflags.set_bit(RFLAGS_RF_BIT, true);
    Ok(InjectionUpdate {
        interruption_info: event.interruption_info(),
        error_code: event.error_code,
        instruction_length: 0,
        guest_rflags: rflags,
    })
}

impl VmEntryEvent {
    pub const fn exception(vector: u8, error_code: Option<u32>) -> Self {
        Self {
            vector,
            interruption_type: InterruptionType::HardwareException,
            error_code,
        }
    }

    pub const fn ud() -> Self {
        Self::exception(VECTOR_INVALID_OPCODE, None)
    }

    pub const fn gp(err: u32) -> Self {
        Self::exception(VECTOR_GENERAL_PROTECTION, Some(err))
    }

    pub const fn interruption_info(self) -> u32 {
        let mut value = self.vector as u32;
        value |= (self.interruption_type as u32) << 8;
        if self.error_code.is_some() {
            value |= 1 << 11;
        }
        value | (1 << 31)
    }
}

// Write the valid interruption field last so partial setup stays inactive.
/// Queues one checked event for the next VM entry.
///
/// # Safety
///
/// The caller is in VMX root with this vCPU's VMCS current and does not resume
/// until this succeeds.
pub unsafe fn apply_event(
    vcpu: &mut Vcpu,
    context: &ExitContext,
    event: VmEntryEvent,
) -> MonadResult<()> {
    let pending = vmread(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD)? as u32;
    let update = prepare_injection(context, event, pending)?;
    if let Some(err) = update.error_code {
        vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, u64::from(err))?;
    }
    vmwrite(
        vmcs::control::VMENTRY_INSTRUCTION_LEN,
        u64::from(update.instruction_length),
    )?;

    vcpu.regs.rflags = update.guest_rflags;
    vmwrite(vmcs::guest::RFLAGS, update.guest_rflags)?;

    vmwrite(
        vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
        u64::from(update.interruption_info),
    )?;
    Ok(())
}

/// Re-queues an event whose delivery was interrupted by the current VM exit.
///
/// # Safety
///
/// The caller is in VMX root with this vCPU's VMCS current and calls this at
/// most once before the next VM entry.
pub unsafe fn apply_vectoring_event(vcpu: &mut Vcpu, context: &ExitContext) -> MonadResult<()> {
    let pending = vmread(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD)? as u32;
    let Some(update) = prepare_reinjection(context, pending)? else {
        return Ok(());
    };
    if let Some(err) = update.error_code {
        vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, u64::from(err))?;
    }
    vmwrite(
        vmcs::control::VMENTRY_INSTRUCTION_LEN,
        u64::from(update.instruction_length),
    )?;
    vcpu.regs.rflags = update.guest_rflags;
    vmwrite(vmcs::guest::RFLAGS, update.guest_rflags)?;
    vmwrite(
        vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
        u64::from(update.interruption_info),
    )?;
    Ok(())
}

pub const fn inject_ud() -> ExitDisposition {
    ExitDisposition::Inject(VmEntryEvent::ud())
}

pub const fn inject_gp() -> ExitDisposition {
    ExitDisposition::Inject(VmEntryEvent::gp(0))
}

#[cfg(test)]
mod tests {
    use crate::ept::ViewId;
    use crate::topology::CpuId;

    use super::*;

    fn context() -> ExitContext {
        ExitContext {
            basic_reason: 48,
            qualification: Some(1),
            instruction_length: None,
            guest_rip: 0x1000,
            guest_rsp: 0x2000,
            guest_rflags: 2,
            guest_cs_selector: 0x10,
            guest_ss_selector: 0x18,
            guest_cs_access: 0,
            guest_ss_access: 0,
            guest_cr0: 0,
            guest_cr3: 0,
            guest_cr4: 0,
            guest_linear_address: None,
            guest_physical_address: Some(0x3000),
            exit_interruption_info: None,
            idt_vectoring_info: None,
            idt_vectoring_error_code: None,
            cpu: CpuId::default(),
            active_view: ViewId {
                slot: 0,
                reserved: 0,
                generation: 1,
            },
            tsc: 0,
        }
    }

    #[test]
    fn injection_uses_explicit_fresh_state() {
        let mut fresh = context();
        fresh.guest_rflags = 0x202;
        fresh.guest_rip = 0x1234;
        let update = prepare_injection(&fresh, VmEntryEvent::gp(7), 0).expect("update");
        assert_eq!(update.guest_rflags, 0x1_0202);
        assert_eq!(update.error_code, Some(7));
        assert_eq!(fresh.guest_rip, 0x1234);
        assert_eq!(update.instruction_length, 0);
        assert!(prepare_injection(&fresh, VmEntryEvent::ud(), 1 << 31).is_err());
        fresh.idt_vectoring_info = Some(1 << 31);
        assert!(prepare_injection(&fresh, VmEntryEvent::ud(), 0).is_err());
    }

    #[test]
    fn vectoring_event_is_reinjected_losslessly() {
        let mut hardware = context();
        hardware.guest_rflags = 0x202;
        hardware.idt_vectoring_info = Some(
            VALID_BIT
                | DELIVER_ERROR_CODE_BIT
                | ((InterruptionType::HardwareException as u32) << TYPE_SHIFT)
                | 14,
        );
        hardware.idt_vectoring_error_code = Some(5);
        let update = prepare_reinjection(&hardware, 0)
            .expect("valid vectoring state")
            .expect("event");
        assert_eq!(
            update.interruption_info,
            hardware.idt_vectoring_info.unwrap()
        );
        assert_eq!(update.error_code, Some(5));
        assert_eq!(update.instruction_length, 0);
        assert_eq!(update.guest_rflags, 0x202);

        let mut software = context();
        software.instruction_length = Some(2);
        software.idt_vectoring_info =
            Some(VALID_BIT | ((InterruptionType::SoftwareInterrupt as u32) << TYPE_SHIFT) | 0x80);
        assert_eq!(
            prepare_reinjection(&software, 0)
                .expect("valid vectoring state")
                .expect("event")
                .instruction_length,
            2
        );
        assert!(prepare_reinjection(&software, VALID_BIT).is_err());
        software.instruction_length = None;
        assert!(prepare_reinjection(&software, 0).is_err());
        software.instruction_length = Some(2);
        software.idt_vectoring_info =
            Some(VALID_BIT | ((InterruptionType::Reserved as u32) << TYPE_SHIFT));
        assert!(prepare_reinjection(&software, 0).is_err());
    }
}
