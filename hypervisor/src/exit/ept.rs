use crate::exit::context::ExitContext;
use crate::telemetry::{EventKind, EventRecord};
use crate::vmm::Vcpu;

use super::disposition::{ExitDisposition, FatalReason};
use super::ept_fault::{
    decode_fault, resolve_disposition, EptFaultPolicy, COMPILED_EPT_FAULT_POLICY,
};

pub fn handle_violation(vcpu: &mut Vcpu, context: &ExitContext) -> ExitDisposition {
    let qualification = match context.qualification {
        Some(value) => value,
        None => return ExitDisposition::Fatal(FatalReason::InvalidVmcsState),
    };
    let fault = match decode_fault(
        qualification,
        context.guest_physical_address,
        context.guest_linear_address,
        context.guest_rip,
    ) {
        Ok(value) => value,
        Err(reason) => return ExitDisposition::Fatal(reason),
    };
    if let Some(events) = unsafe { vcpu.events.as_ref() } {
        events.record(vcpu.stamp_event(EventRecord::from_exit(
            context,
            EventKind::EptViolation,
            fault.access.bits(),
            0,
            0,
        )));
    }
    let directory = unsafe { vcpu.published_views.as_ref() };
    resolve_disposition(
        policy(),
        vcpu.cpu,
        vcpu.active_view.id,
        &fault,
        &mut vcpu.fault_tracker,
        vcpu.allowed_fault_views,
        |view| directory.is_some_and(|views| views.resolve(view).is_some()),
    )
}

pub const fn handle_misconfig(_guest_physical_address: u64) -> ExitDisposition {
    ExitDisposition::Fatal(FatalReason::CorruptEptHierarchy)
}

fn policy() -> &'static dyn EptFaultPolicy {
    &COMPILED_EPT_FAULT_POLICY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ept_violation_does_not_advance() {
        let disposition = ExitDisposition::Fatal(FatalReason::UnhandledEptViolation);
        assert!(!disposition.advances_rip());
    }

    #[test]
    fn ept_fault_never_advances_or_writes_tables() {
        for disposition in [
            ExitDisposition::ResumeWithoutAdvance,
            ExitDisposition::SwitchPublishedView(crate::ept::ViewId {
                slot: 1,
                reserved: 0,
                generation: 1,
            }),
            ExitDisposition::Fatal(FatalReason::InvalidVmcsState),
        ] {
            assert!(!disposition.advances_rip());
        }
        let source = include_str!("ept.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or("");
        assert!(!production.contains("write_entry"));
        assert!(!production.contains("entries_mut"));
        assert!(!production.contains("apply_batch"));
    }

    #[test]
    fn root_path_contract() {
        let sources = [
            include_str!("ept.rs"),
            include_str!("ept_fault.rs"),
            include_str!("vmexit.rs"),
        ];
        let forbidden = [
            concat!("Box", "::"),
            concat!("Vec", "::"),
            concat!("log", "::"),
            concat!("format", "!"),
            concat!("String", "::"),
            concat!("Mutex", "::"),
            concat!("write", "_entry"),
        ];
        for source in sources {
            let production = source.split("#[cfg(test)]").next().unwrap_or("");
            for pattern in forbidden {
                assert!(!production.contains(pattern), "root path has {pattern}");
            }
        }
    }
}
