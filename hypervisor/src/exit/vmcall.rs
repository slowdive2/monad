// vmcalls only come from known cpl0 rendezvous callbacks.
// guest registers never carry commands, pointers, or service data.

#[cfg(not(test))]
use wdk_sys::{ntddk::KeGetCurrentProcessorNumberEx, PROCESSOR_NUMBER};
use x86::vmx::vmcs;

use crate::arch::intel::{
    invept::invept_single,
    vmx::{vmread, vmwrite},
};
use crate::error::MonadResult;
use crate::rendezvous::{
    switch_view, MailboxValidation, RendezvousOperation, SwitchStep, ViewSwitchBackend,
};
use crate::topology::CpuId;
use crate::vmm::Vcpu;

use super::disposition::{ExitDisposition, FatalReason};
use super::eventinjection::inject_ud;

struct HardwareSwitch;

impl ViewSwitchBackend for HardwareSwitch {
    fn run(&mut self, _cpu: u16, step: SwitchStep, eptp: u64) -> MonadResult<()> {
        match step {
            SwitchStep::WriteTarget | SwitchStep::RestoreOld => {
                vmwrite(vmcs::control::EPTP_FULL, eptp)
            }
            SwitchStep::InvalidateOld
            | SwitchStep::InvalidateTarget
            | SwitchStep::InvalidateFailedTarget
            | SwitchStep::InvalidateRestoredOld => {
                // safety: the capability gate requires single-context invept.
                unsafe { invept_single(eptp) }
            }
        }
    }
}

#[cfg(not(test))]
fn current_cpu(expected: CpuId) -> CpuId {
    let mut native = PROCESSOR_NUMBER::default();
    // safety: native is a writable processor-number output.
    unsafe { KeGetCurrentProcessorNumberEx(&mut native) };
    CpuId {
        dense_index: expected.dense_index,
        group: native.Group,
        number: native.Number,
        reserved: [0; 3],
    }
}

#[cfg(test)]
fn current_cpu(expected: CpuId) -> CpuId {
    expected
}

/// handles one private shutdown vmcall.
///
/// # Safety
///
/// the caller is in vmx root with this vcpu's vmcs current and exclusive access.
/// only its rendezvous callback may arm the mailbox.
pub(super) unsafe fn handle(vcpu: &mut Vcpu) -> ExitDisposition {
    // cs.rpl equals cpl. a nonzero rpl means user mode and receives #ud.
    let cs = match vmread(vmcs::guest::CS_SELECTOR) {
        Ok(v) => v,
        Err(_) => return ExitDisposition::Fatal(FatalReason::VmreadFailure),
    };
    let directory = unsafe { vcpu.published_views.as_ref() };
    let resolved = vcpu
        .mailbox
        .prepared_target()
        .and_then(|id| directory.and_then(|views| views.resolve(id)));
    let validation = MailboxValidation {
        cs_selector: cs as u16,
        expected_cpu: vcpu.cpu,
        current_cpu: current_cpu(vcpu.cpu),
        active_epoch: vcpu
            .rendezvous_epoch
            .load(core::sync::atomic::Ordering::Acquire),
        active_view: vcpu.active_view.id,
        active_eptp: vcpu.active_view.eptp,
        resolved_target_eptp: resolved,
    };
    let request = match vcpu.mailbox.consume(validation) {
        Ok(request) => request,
        Err(_) => return inject_ud(),
    };
    if request.operation == RendezvousOperation::Shutdown {
        if vcpu.mailbox.complete().is_err() {
            return ExitDisposition::Fatal(FatalReason::InvalidVcpuState);
        }
        return ExitDisposition::Shutdown;
    }
    let mut hardware = HardwareSwitch;
    let result = switch_view(
        vcpu.cpu.dense_index,
        &mut vcpu.active_view,
        request,
        &vcpu.mailbox,
        &mut hardware,
    );
    vcpu.active_report.publish(vcpu.active_view);
    match (request.operation, result) {
        (_, Ok(())) => ExitDisposition::ResumeAndAdvance,
        (RendezvousOperation::SwitchView, Err(_)) => ExitDisposition::ResumeAndAdvance,
        (RendezvousOperation::RollbackView, Err(_)) => {
            ExitDisposition::Fatal(FatalReason::InvalidVcpuState)
        }
        (RendezvousOperation::Shutdown, Err(_)) => {
            ExitDisposition::Fatal(FatalReason::InvalidVcpuState)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::{InternalMailbox, MailboxRequest, MailboxState};

    #[test]
    fn public_vmcall_is_ud() {
        let mailbox = InternalMailbox::new();

        // guest register noise cannot affect the private mailbox.
        for guest_value in [0, 1, u32::MAX as u64, u64::MAX] {
            let regs = crate::arch::intel::vmcs::GuestRegs {
                rax: guest_value,
                rcx: !guest_value,
                rdx: guest_value.rotate_left(17),
                r10: guest_value.rotate_right(11),
                ..Default::default()
            };
            let before = mailbox.state();
            assert_eq!(before, Some(MailboxState::Idle));
            assert_eq!(
                (regs.rax, regs.rcx, regs.rdx, regs.r10),
                (
                    guest_value,
                    !guest_value,
                    guest_value.rotate_left(17),
                    guest_value.rotate_right(11)
                )
            );
        }
    }

    #[test]
    fn private_shutdown_requires_cpl0_and_mailbox() {
        let mailbox = InternalMailbox::new();
        mailbox
            .prepare(MailboxRequest {
                epoch: 1,
                operation: RendezvousOperation::Shutdown,
                target_view: crate::ept::ViewId {
                    slot: 0,
                    reserved: 0,
                    generation: 1,
                },
                target_eptp: 0x1000,
                expected_old_eptp: 0x1000,
            })
            .expect("prepare");
        assert_eq!(mailbox.state(), Some(MailboxState::Prepared));
    }
}
