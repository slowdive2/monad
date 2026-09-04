use crate::ept::ViewId;
use crate::topology::CpuId;

use super::disposition::{ExitDisposition, FatalReason};
use super::eventinjection::VmEntryEvent;

pub const MAX_IDENTICAL_EPT_RETRIES: u8 = 2;
pub const COMPILED_ALLOWED_VIEW_MASK: u64 = (1u64 << crate::ept::MAX_PUBLISHED_VIEWS) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptFaultAccess(u8);

impl EptFaultAccess {
    pub const READ: u8 = 1;
    pub const WRITE: u8 = 2;
    pub const EXECUTE: u8 = 4;

    pub const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptFault {
    pub qualification: u64,
    pub guest_physical_address: u64,
    pub guest_physical_page: u64,
    pub guest_linear_address: Option<u64>,
    pub guest_rip: u64,
    pub access: EptFaultAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EptFaultDisposition {
    Fatal(FatalReason),
    Inject(VmEntryEvent),
    SwitchToPublishedView(ViewId),
    RetryCurrentView,
}

pub trait EptFaultPolicy: Sync {
    fn handle(&self, cpu: CpuId, active_view: ViewId, fault: &EptFault) -> EptFaultDisposition;
}

pub struct ResearchEptFaultPolicy;

impl EptFaultPolicy for ResearchEptFaultPolicy {
    fn handle(&self, _cpu: CpuId, _active_view: ViewId, _fault: &EptFault) -> EptFaultDisposition {
        EptFaultDisposition::Fatal(FatalReason::UnhandledEptViolation)
    }
}

pub static COMPILED_EPT_FAULT_POLICY: ResearchEptFaultPolicy = ResearchEptFaultPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptFaultSignature {
    pub view: ViewId,
    pub gpa_page: u64,
    pub rip: u64,
    pub access: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct EptFaultTracker {
    last: Option<EptFaultSignature>,
    retries: u8,
}

impl EptFaultTracker {
    pub const fn new() -> Self {
        Self {
            last: None,
            retries: 0,
        }
    }

    pub fn permit_retry(&mut self, signature: EptFaultSignature) -> bool {
        if self.last != Some(signature) {
            self.last = Some(signature);
            self.retries = 1;
            return true;
        }
        if self.retries >= MAX_IDENTICAL_EPT_RETRIES {
            return false;
        }
        self.retries += 1;
        true
    }

    pub fn reset(&mut self) {
        self.last = None;
        self.retries = 0;
    }
}

impl Default for EptFaultTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn decode_fault(
    qualification: u64,
    guest_physical_address: Option<u64>,
    guest_linear_address: Option<u64>,
    guest_rip: u64,
) -> Result<EptFault, FatalReason> {
    const SUPPORTED_QUALIFICATION_BITS: u64 = 0x1fff;
    if qualification & !SUPPORTED_QUALIFICATION_BITS != 0 {
        return Err(FatalReason::InvalidVmcsState);
    }
    let access = (qualification & 7) as u8;
    if access == 0 {
        return Err(FatalReason::InvalidVmcsState);
    }
    let gpa = guest_physical_address.ok_or(FatalReason::InvalidVmcsState)?;
    if gpa >= (1u64 << 48) {
        return Err(FatalReason::InvalidVmcsState);
    }
    let gla_valid = qualification & (1 << 7) != 0;
    if gla_valid != guest_linear_address.is_some() {
        return Err(FatalReason::InvalidVmcsState);
    }
    Ok(EptFault {
        qualification,
        guest_physical_address: gpa,
        guest_physical_page: gpa & !0xfff,
        guest_linear_address,
        guest_rip,
        access: EptFaultAccess(access),
    })
}

pub fn resolve_disposition(
    policy: &dyn EptFaultPolicy,
    cpu: CpuId,
    active_view: ViewId,
    fault: &EptFault,
    tracker: &mut EptFaultTracker,
    allowed_view_mask: u64,
    mut view_exists: impl FnMut(ViewId) -> bool,
) -> ExitDisposition {
    match policy.handle(cpu, active_view, fault) {
        EptFaultDisposition::Fatal(reason) => ExitDisposition::Fatal(reason),
        EptFaultDisposition::Inject(event) => ExitDisposition::Inject(event),
        EptFaultDisposition::RetryCurrentView => {
            let signature = EptFaultSignature {
                view: active_view,
                gpa_page: fault.guest_physical_page,
                rip: fault.guest_rip,
                access: fault.access.bits(),
            };
            if tracker.permit_retry(signature) {
                ExitDisposition::ResumeWithoutAdvance
            } else {
                ExitDisposition::Fatal(FatalReason::RepeatedEptFault)
            }
        }
        EptFaultDisposition::SwitchToPublishedView(view) => {
            let allowed = view.slot < 64 && allowed_view_mask & (1u64 << view.slot) != 0;
            if view.reserved != 0 || view.generation == 0 || !allowed || !view_exists(view) {
                return ExitDisposition::Fatal(FatalReason::InvalidActiveView);
            }
            tracker.reset();
            ExitDisposition::SwitchPublishedView(view)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu() -> CpuId {
        CpuId {
            dense_index: 0,
            group: 0,
            number: 0,
            reserved: [0; 3],
        }
    }

    fn view(slot: u16) -> ViewId {
        ViewId {
            slot,
            reserved: 0,
            generation: 1,
        }
    }

    fn fault() -> EptFault {
        decode_fault(1, Some(0x1234), None, 0x4000).expect("fault")
    }

    struct Fixed(EptFaultDisposition);

    impl EptFaultPolicy for Fixed {
        fn handle(
            &self,
            _cpu: CpuId,
            _active_view: ViewId,
            _fault: &EptFault,
        ) -> EptFaultDisposition {
            self.0
        }
    }

    #[test]
    fn fault_access_decode() {
        for access in 1..=7u64 {
            let decoded = decode_fault(access, Some(0x1234), None, 9).expect("access");
            assert_eq!(u64::from(decoded.access.bits()), access);
            assert_eq!(decoded.guest_physical_page, 0x1000);
        }
        assert!(decode_fault(0, Some(0), None, 0).is_err());
        assert!(decode_fault(1, None, None, 0).is_err());
        assert!(decode_fault(1 << 63 | 1, Some(0), None, 0).is_err());
        assert!(decode_fault(1 | 1 << 7, Some(0), None, 0).is_err());
        assert!(decode_fault(1, Some(1u64 << 48), None, 0).is_err());
        assert!(decode_fault(1 | 1 << 7, Some(0), Some(7), 0).is_ok());
    }

    #[test]
    fn fault_disposition_table() {
        let mut tracker = EptFaultTracker::new();
        let fatal = Fixed(EptFaultDisposition::Fatal(FatalReason::CorruptEptHierarchy));
        assert_eq!(
            resolve_disposition(&fatal, cpu(), view(0), &fault(), &mut tracker, 3, |_| true),
            ExitDisposition::Fatal(FatalReason::CorruptEptHierarchy)
        );
        let inject = Fixed(EptFaultDisposition::Inject(VmEntryEvent::ud()));
        assert!(matches!(
            resolve_disposition(&inject, cpu(), view(0), &fault(), &mut tracker, 3, |_| true),
            ExitDisposition::Inject(_)
        ));
        let switch = Fixed(EptFaultDisposition::SwitchToPublishedView(view(1)));
        assert_eq!(
            resolve_disposition(&switch, cpu(), view(0), &fault(), &mut tracker, 3, |_| true),
            ExitDisposition::SwitchPublishedView(view(1))
        );
        assert_eq!(
            resolve_disposition(&switch, cpu(), view(0), &fault(), &mut tracker, 1, |_| true),
            ExitDisposition::Fatal(FatalReason::InvalidActiveView)
        );
        assert_eq!(
            resolve_disposition(&switch, cpu(), view(0), &fault(), &mut tracker, 3, |_| {
                false
            }),
            ExitDisposition::Fatal(FatalReason::InvalidActiveView)
        );
        let retry = Fixed(EptFaultDisposition::RetryCurrentView);
        assert_eq!(
            resolve_disposition(&retry, cpu(), view(0), &fault(), &mut tracker, 3, |_| true),
            ExitDisposition::ResumeWithoutAdvance
        );
    }

    #[test]
    fn identical_fault_limit() {
        let retry = Fixed(EptFaultDisposition::RetryCurrentView);
        let mut tracker = EptFaultTracker::new();
        for _ in 0..MAX_IDENTICAL_EPT_RETRIES {
            assert_eq!(
                resolve_disposition(&retry, cpu(), view(0), &fault(), &mut tracker, 1, |_| true),
                ExitDisposition::ResumeWithoutAdvance
            );
        }
        assert_eq!(
            resolve_disposition(&retry, cpu(), view(0), &fault(), &mut tracker, 1, |_| true),
            ExitDisposition::Fatal(FatalReason::RepeatedEptFault)
        );
        let changed_view =
            resolve_disposition(&retry, cpu(), view(1), &fault(), &mut tracker, 3, |_| true);
        assert_eq!(changed_view, ExitDisposition::ResumeWithoutAdvance);
        let mut changed_fault = fault();
        changed_fault.guest_rip += 1;
        assert_eq!(
            resolve_disposition(
                &retry,
                cpu(),
                view(1),
                &changed_fault,
                &mut tracker,
                3,
                |_| true
            ),
            ExitDisposition::ResumeWithoutAdvance
        );
    }
}
