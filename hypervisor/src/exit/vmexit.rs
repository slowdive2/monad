use crate::arch::intel::invept::invept_single;
use crate::arch::intel::state::read_tsc;
use crate::arch::intel::vmx::{vmread, vmwrite};
use crate::error::MonadResult;
use crate::exit::context::{
    capture_exit_context, ContextField, ContextReader, ExitContext, ExitFieldValidity,
};
use crate::exit::disposition::{ExitDisposition, FatalReason};
use crate::telemetry::{EventKind, EventRecord};
use crate::vmm::Vcpu;
use x86::vmx::vmcs;

use super::{cpuid, ept, eventinjection, genericvmx, msr, triplefault, vmcall};

mod exit_reason {
    pub const TRIPLE_FAULT: u64 = 2;
    pub const CPUID: u64 = 10;
    pub const VMCALL: u64 = 18;
    pub const VMCLEAR: u64 = 19;
    pub const VMLAUNCH: u64 = 20;
    pub const VMPTRLD: u64 = 21;
    pub const VMPTRST: u64 = 22;
    pub const VMREAD: u64 = 23;
    pub const VMRESUME: u64 = 24;
    pub const VMWRITE: u64 = 25;
    pub const VMXOFF: u64 = 26;
    pub const VMXON: u64 = 27;
    pub const RDMSR: u64 = 31;
    pub const WRMSR: u64 = 32;
    pub const EPT_VIOLATION: u64 = 48;
    pub const EPT_MISCONFIGURATION: u64 = 49;
    pub const INVEPT: u64 = 50;
    pub const INVVPID: u64 = 53;
    pub const XSETBV: u64 = 55;
    pub const VMFUNC: u64 = 59;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitRoute {
    TripleFault,
    Cpuid,
    Xsetbv,
    Vmcall,
    GuestVmxInstruction,
    Rdmsr,
    Wrmsr,
    EptViolation,
    EptMisconfiguration,
    Unknown,
}

const fn route_exit_reason(reason: u64) -> ExitRoute {
    match reason {
        exit_reason::TRIPLE_FAULT => ExitRoute::TripleFault,
        exit_reason::CPUID => ExitRoute::Cpuid,
        exit_reason::XSETBV => ExitRoute::Xsetbv,
        exit_reason::VMCALL => ExitRoute::Vmcall,
        exit_reason::VMCLEAR
        | exit_reason::VMLAUNCH
        | exit_reason::VMPTRLD
        | exit_reason::VMPTRST
        | exit_reason::VMREAD
        | exit_reason::VMRESUME
        | exit_reason::VMWRITE
        | exit_reason::VMXOFF
        | exit_reason::VMXON
        | exit_reason::INVEPT
        | exit_reason::INVVPID
        | exit_reason::VMFUNC => ExitRoute::GuestVmxInstruction,
        exit_reason::RDMSR => ExitRoute::Rdmsr,
        exit_reason::WRMSR => ExitRoute::Wrmsr,
        exit_reason::EPT_VIOLATION => ExitRoute::EptViolation,
        exit_reason::EPT_MISCONFIGURATION => ExitRoute::EptMisconfiguration,
        _ => ExitRoute::Unknown,
    }
}

const fn unknown_exit_disposition() -> ExitDisposition {
    ExitDisposition::Fatal(FatalReason::UnexpectedVmExit)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExitAction {
    Resume,
    Shutdown,
    Fatal(FatalReason),
}

struct HardwareContextReader;

impl ContextReader for HardwareContextReader {
    fn read(&mut self, field: ContextField) -> MonadResult<u64> {
        vmread(match field {
            ContextField::ExitReason => vmcs::ro::EXIT_REASON,
            ContextField::Qualification => vmcs::ro::EXIT_QUALIFICATION,
            ContextField::InstructionLength => vmcs::ro::VMEXIT_INSTRUCTION_LEN,
            ContextField::GuestRip => vmcs::guest::RIP,
            ContextField::GuestRsp => vmcs::guest::RSP,
            ContextField::GuestRflags => vmcs::guest::RFLAGS,
            ContextField::GuestCsSelector => vmcs::guest::CS_SELECTOR,
            ContextField::GuestSsSelector => vmcs::guest::SS_SELECTOR,
            ContextField::GuestCsAccess => vmcs::guest::CS_ACCESS_RIGHTS,
            ContextField::GuestSsAccess => vmcs::guest::SS_ACCESS_RIGHTS,
            ContextField::GuestCr0 => vmcs::guest::CR0,
            ContextField::GuestCr3 => vmcs::guest::CR3,
            ContextField::GuestCr4 => vmcs::guest::CR4,
            ContextField::GuestLinearAddress => vmcs::ro::GUEST_LINEAR_ADDR,
            ContextField::GuestPhysicalAddress => vmcs::ro::GUEST_PHYSICAL_ADDR_FULL,
            ContextField::ExitInterruptionInfo => vmcs::ro::VMEXIT_INTERRUPTION_INFO,
            ContextField::IdtVectoringInfo => vmcs::ro::IDT_VECTORING_INFO,
            ContextField::IdtVectoringErrorCode => vmcs::ro::IDT_VECTORING_ERR_CODE,
        })
    }
}

fn capture(vcpu: &Vcpu) -> MonadResult<ExitContext> {
    let reason = vmread(vmcs::ro::EXIT_REASON)? & 0xffff;
    let qualification = if reason == exit_reason::EPT_VIOLATION {
        vmread(vmcs::ro::EXIT_QUALIFICATION)?
    } else {
        0
    };
    let exit_info = vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO)? as u32;
    let idt_info = vmread(vmcs::ro::IDT_VECTORING_INFO)? as u32;
    let mut validity = ExitFieldValidity::for_basic_reason(reason as u16, qualification);
    validity.exit_interruption_info = exit_info & (1 << 31) != 0;
    validity.idt_vectoring_info = idt_info & (1 << 31) != 0;
    validity.idt_vectoring_error_code = validity.idt_vectoring_info && idt_info & (1 << 11) != 0;
    let vectoring_type = (idt_info >> 8) & 0x7;
    validity.instruction_length |= validity.idt_vectoring_info && matches!(vectoring_type, 4..=6);
    capture_exit_context(
        &mut HardwareContextReader,
        validity,
        vcpu.cpu,
        vcpu.active_view.id,
        read_tsc(),
    )
}

fn record(vcpu: &Vcpu, event: EventRecord) {
    if let Some(events) = unsafe { vcpu.events.as_ref() } {
        events.record(event);
    }
}

fn fatal(vcpu: &mut Vcpu, context: &ExitContext, reason: FatalReason) -> VmExitAction {
    let event = vcpu.stamp_event(EventRecord::from_exit(
        context,
        EventKind::Fatal,
        0,
        reason as u32,
        0,
    ));
    vcpu.emergency_event = event;
    record(vcpu, event);
    VmExitAction::Fatal(reason)
}

fn advance_rip(vcpu: &mut Vcpu, context: &ExitContext) -> MonadResult<()> {
    let len = u64::from(context.instruction_length.ok_or_else(|| {
        crate::error::MonadError::new(
            crate::error::ErrorPhase::ExitHandling,
            crate::error::ErrorCode::InvalidGuestState,
            context.basic_reason as u64,
        )
    })?);
    let next = context.guest_rip.checked_add(len).ok_or_else(|| {
        crate::error::MonadError::new(
            crate::error::ErrorPhase::ExitHandling,
            crate::error::ErrorCode::InvalidGuestState,
            len,
        )
    })?;
    vmwrite(vmcs::guest::RIP, next)?;
    vcpu.regs.rip = next;
    Ok(())
}

fn switch_local_view(vcpu: &mut Vcpu, view: crate::ept::ViewId) -> Result<(), FatalReason> {
    let directory =
        unsafe { vcpu.published_views.as_ref() }.ok_or(FatalReason::InvalidActiveView)?;
    let target = directory
        .resolve(view)
        .ok_or(FatalReason::InvalidActiveView)?;
    if vmwrite(vmcs::control::EPTP_FULL, target).is_err() {
        return Err(FatalReason::VmwriteFailure);
    }
    if unsafe { invept_single(target) }.is_err() {
        let old = vcpu.active_view.eptp;
        if vmwrite(vmcs::control::EPTP_FULL, old).is_err() || unsafe { invept_single(old) }.is_err()
        {
            return Err(FatalReason::InveptFailure);
        }
        return Err(FatalReason::InveptFailure);
    }
    vcpu.active_view.id = view;
    vcpu.active_view.eptp = target;
    if !vcpu.commit_view_epoch() {
        return Err(FatalReason::InvalidVcpuState);
    }
    vcpu.record_transition(EventKind::ViewSwitch, 0, 1);
    Ok(())
}

/// dispatches one exit for the current vcpu.
///
/// # Safety
///
/// the caller runs on `vcpu`'s root stack with its vmcs current and exclusive
/// mutable access.
pub unsafe fn handle(vcpu: &mut Vcpu) -> VmExitAction {
    let context = match capture(vcpu) {
        Ok(value) => value,
        Err(_) => {
            let fallback = ExitContext {
                basic_reason: 0,
                qualification: None,
                instruction_length: None,
                guest_rip: 0,
                guest_rsp: 0,
                guest_rflags: 0,
                guest_cs_selector: 0,
                guest_ss_selector: 0,
                guest_cs_access: 0,
                guest_ss_access: 0,
                guest_cr0: 0,
                guest_cr3: 0,
                guest_cr4: 0,
                guest_linear_address: None,
                guest_physical_address: None,
                exit_interruption_info: None,
                idt_vectoring_info: None,
                idt_vectoring_error_code: None,
                cpu: vcpu.cpu,
                active_view: vcpu.active_view.id,
                tsc: read_tsc(),
            };
            return fatal(vcpu, &fallback, FatalReason::VmreadFailure);
        }
    };
    vcpu.regs.rip = context.guest_rip;
    vcpu.regs.rsp = context.guest_rsp;
    vcpu.regs.rflags = context.guest_rflags;

    let disposition = match route_exit_reason(u64::from(context.basic_reason)) {
        ExitRoute::Cpuid => cpuid::handle(vcpu, context.guest_cr4),
        ExitRoute::Xsetbv => {
            super::xsetbv::handle(vcpu, context.guest_cs_selector, context.guest_cr4)
        }
        ExitRoute::Rdmsr => msr::handle(vcpu, false),
        ExitRoute::Wrmsr => {
            let disposition = msr::handle(vcpu, true);
            if matches!(
                disposition,
                ExitDisposition::Fatal(FatalReason::MtrrChangedWhileRunning)
            ) {
                record(
                    vcpu,
                    vcpu.stamp_event(EventRecord::from_exit(
                        &context,
                        EventKind::MtrrModificationAttempt,
                        0,
                        0,
                        vcpu.regs.rcx as u32,
                    )),
                );
            }
            disposition
        }
        ExitRoute::TripleFault => triplefault::handle(vcpu),
        ExitRoute::EptViolation => ept::handle_violation(vcpu, &context),
        ExitRoute::EptMisconfiguration => {
            ept::handle_misconfig(context.guest_physical_address.unwrap_or(0))
        }
        ExitRoute::Vmcall => unsafe { vmcall::handle(vcpu) },
        ExitRoute::GuestVmxInstruction => genericvmx::handle(vcpu),
        ExitRoute::Unknown => {
            record(
                vcpu,
                vcpu.stamp_event(EventRecord::from_exit(
                    &context,
                    EventKind::UnexpectedVmExit,
                    0,
                    context.basic_reason as u32,
                    0,
                )),
            );
            unknown_exit_disposition()
        }
    };

    apply(vcpu, &context, disposition)
}

fn apply(vcpu: &mut Vcpu, context: &ExitContext, disposition: ExitDisposition) -> VmExitAction {
    let resume =
        |vcpu: &mut Vcpu| match unsafe { eventinjection::apply_vectoring_event(vcpu, context) } {
            Ok(()) => VmExitAction::Resume,
            Err(_) => fatal(vcpu, context, FatalReason::VmwriteFailure),
        };
    match disposition {
        ExitDisposition::ResumeAndAdvance => match advance_rip(vcpu, context) {
            Ok(()) => resume(vcpu),
            Err(_) => fatal(vcpu, context, FatalReason::VmwriteFailure),
        },
        ExitDisposition::ResumeWithoutAdvance => resume(vcpu),
        ExitDisposition::Inject(event) => {
            match unsafe { eventinjection::apply_event(vcpu, context, event) } {
                Ok(()) => VmExitAction::Resume,
                Err(_) => fatal(vcpu, context, FatalReason::VmwriteFailure),
            }
        }
        ExitDisposition::SwitchPublishedView(view) => match switch_local_view(vcpu, view) {
            Ok(()) => resume(vcpu),
            Err(reason) => fatal(vcpu, context, reason),
        },
        ExitDisposition::Shutdown => VmExitAction::Shutdown,
        ExitDisposition::Fatal(reason) => fatal(vcpu, context, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_known_reason() {
        let cases = [
            (exit_reason::TRIPLE_FAULT, ExitRoute::TripleFault),
            (exit_reason::CPUID, ExitRoute::Cpuid),
            (exit_reason::VMCALL, ExitRoute::Vmcall),
            (exit_reason::VMCLEAR, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMLAUNCH, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMPTRLD, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMPTRST, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMREAD, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMRESUME, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMWRITE, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMXOFF, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMXON, ExitRoute::GuestVmxInstruction),
            (exit_reason::RDMSR, ExitRoute::Rdmsr),
            (exit_reason::WRMSR, ExitRoute::Wrmsr),
            (exit_reason::EPT_VIOLATION, ExitRoute::EptViolation),
            (
                exit_reason::EPT_MISCONFIGURATION,
                ExitRoute::EptMisconfiguration,
            ),
            (exit_reason::INVEPT, ExitRoute::GuestVmxInstruction),
            (exit_reason::INVVPID, ExitRoute::GuestVmxInstruction),
            (exit_reason::VMFUNC, ExitRoute::GuestVmxInstruction),
        ];
        for (reason, expected) in cases {
            assert_eq!(route_exit_reason(reason), expected, "reason {reason}");
        }
    }

    #[test]
    fn dispatch_unknown_is_fatal() {
        assert_eq!(route_exit_reason(u64::MAX), ExitRoute::Unknown);
        let disposition = unknown_exit_disposition();
        assert_eq!(
            disposition,
            ExitDisposition::Fatal(FatalReason::UnexpectedVmExit)
        );
        assert!(!disposition.advances_rip());
    }
}
