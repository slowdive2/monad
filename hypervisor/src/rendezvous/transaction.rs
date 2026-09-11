extern crate alloc;

#[cfg(test)]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ept::ViewId;
use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};
use crate::topology::MAX_LOGICAL_CPUS;

use super::{InternalMailbox, MailboxRequest, MailboxStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveViewState {
    pub id: ViewId,
    pub eptp: u64,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchStep {
    WriteTarget = 1,
    InvalidateOld = 2,
    InvalidateTarget = 3,
    RestoreOld = 4,
    InvalidateFailedTarget = 5,
    InvalidateRestoredOld = 6,
}

pub trait ViewSwitchBackend {
    fn run(&mut self, cpu: u16, step: SwitchStep, eptp: u64) -> MonadResult<()>;
}

/// An error is resumable only when recovery is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchFailure {
    pub forward: MonadError,
    pub recovery: Option<MonadError>,
}

impl From<MonadError> for SwitchFailure {
    fn from(forward: MonadError) -> Self {
        Self {
            forward,
            recovery: None,
        }
    }
}

pub fn switch_view<B: ViewSwitchBackend>(
    cpu: u16,
    active: &mut ActiveViewState,
    request: MailboxRequest,
    mailbox: &InternalMailbox,
    backend: &mut B,
) -> Result<(), SwitchFailure> {
    if active.eptp != request.expected_old_eptp {
        mailbox.fail(MailboxStatus::OldViewMismatch);
        return Err(MonadError::new(
            ErrorPhase::Activation,
            ErrorCode::WrongObjectState,
            active.eptp,
        )
        .on_cpu(cpu)
        .into());
    }
    let old = *active;
    let steps = [
        (SwitchStep::WriteTarget, request.target_eptp),
        (SwitchStep::InvalidateOld, old.eptp),
        (SwitchStep::InvalidateTarget, request.target_eptp),
    ];
    for (step, eptp) in steps {
        if let Err(error) = backend.run(cpu, step, eptp) {
            mailbox.fail(MailboxStatus::SwitchFailed);
            let recovery = restore_after_failure(cpu, old.eptp, request.target_eptp, backend)
                .err()
                .map(|error| error.on_cpu(cpu));
            return Err(SwitchFailure {
                forward: error.on_cpu(cpu),
                recovery,
            });
        }
    }
    active.id = request.target_view;
    active.eptp = request.target_eptp;
    mailbox.complete().map_err(|status| {
        let error = MonadError::new(
            ErrorPhase::Activation,
            ErrorCode::WrongObjectState,
            status as u64,
        )
        .on_cpu(cpu);
        SwitchFailure {
            forward: error,
            recovery: Some(error),
        }
    })
}

fn restore_after_failure<B: ViewSwitchBackend>(
    cpu: u16,
    old_eptp: u64,
    target_eptp: u64,
    backend: &mut B,
) -> MonadResult<()> {
    backend.run(cpu, SwitchStep::RestoreOld, old_eptp)?;
    backend.run(cpu, SwitchStep::InvalidateFailedTarget, target_eptp)?;
    backend.run(cpu, SwitchStep::InvalidateRestoredOld, old_eptp)
}

pub fn rollback_view<B: ViewSwitchBackend>(
    cpu: u16,
    active: &mut ActiveViewState,
    old: ActiveViewState,
    backend: &mut B,
) -> MonadResult<()> {
    let current = *active;
    backend.run(cpu, SwitchStep::RestoreOld, old.eptp)?;
    backend.run(cpu, SwitchStep::InvalidateFailedTarget, current.eptp)?;
    backend.run(cpu, SwitchStep::InvalidateRestoredOld, old.eptp)?;
    *active = old;
    Ok(())
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuResultState {
    Waiting = 0,
    NotTarget = 1,
    Switched = 2,
    Failed = 3,
    RolledBack = 4,
    Fatal = 5,
}

pub struct RendezvousCpuResult {
    state: AtomicU32,
    status: AtomicU32,
}

impl RendezvousCpuResult {
    fn new() -> Self {
        Self {
            state: AtomicU32::new(CpuResultState::Waiting as u32),
            status: AtomicU32::new(0),
        }
    }

    pub fn state(&self) -> u32 {
        self.state.load(Ordering::Acquire)
    }

    pub fn status(&self) -> u32 {
        self.status.load(Ordering::Acquire)
    }
}

pub struct RendezvousTransaction {
    pub epoch: u64,
    target_mask: [bool; MAX_LOGICAL_CPUS],
    pub participant_count: u32,
    pub arrived: AtomicU32,
    pub finished: AtomicU32,
    pub rollback_finished: AtomicU32,
    pub failed: AtomicBool,
    pub fatal: AtomicBool,
    pub release: AtomicBool,
    pub per_cpu: [RendezvousCpuResult; MAX_LOGICAL_CPUS],
    deadline_tsc: u64,
}

impl RendezvousTransaction {
    pub fn new(
        epoch: u64,
        participant_count: u16,
        targets: &[u16],
        deadline_tsc: u64,
    ) -> MonadResult<Self> {
        if epoch == 0 || participant_count == 0 || participant_count as usize > MAX_LOGICAL_CPUS {
            return Err(MonadError::new(
                ErrorPhase::Rendezvous,
                ErrorCode::InvalidCpuSet,
                u64::from(participant_count),
            ));
        }
        let mut target_mask = [false; MAX_LOGICAL_CPUS];
        for target in targets {
            let slot = target_mask.get_mut(usize::from(*target)).ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::Rendezvous,
                    ErrorCode::InvalidCpuSet,
                    u64::from(*target),
                )
            })?;
            if *slot || *target >= participant_count {
                return Err(MonadError::new(
                    ErrorPhase::Rendezvous,
                    ErrorCode::InvalidCpuSet,
                    u64::from(*target),
                ));
            }
            *slot = true;
        }
        if targets.is_empty() {
            return Err(MonadError::new(
                ErrorPhase::Rendezvous,
                ErrorCode::InvalidCpuSet,
                0,
            ));
        }
        Ok(Self {
            epoch,
            target_mask,
            participant_count: u32::from(participant_count),
            arrived: AtomicU32::new(0),
            finished: AtomicU32::new(0),
            rollback_finished: AtomicU32::new(0),
            failed: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            release: AtomicBool::new(false),
            per_cpu: core::array::from_fn(|_| RendezvousCpuResult::new()),
            deadline_tsc,
        })
    }

    pub fn is_target(&self, cpu: u16) -> bool {
        self.target_mask
            .get(usize::from(cpu))
            .copied()
            .unwrap_or(false)
    }

    pub fn deadline_tsc(&self) -> u64 {
        self.deadline_tsc
    }

    pub fn wait_for(&self, counter: &AtomicU32, mut read_tsc: impl FnMut() -> u64) -> bool {
        while counter.load(Ordering::Acquire) != self.participant_count {
            if read_tsc() >= self.deadline_tsc {
                self.fatal.store(true, Ordering::Release);
                return false;
            }
            core::hint::spin_loop();
        }
        true
    }

    pub(crate) fn set_result(&self, cpu: u16, state: CpuResultState, status: u32) {
        if let Some(result) = self.per_cpu.get(usize::from(cpu)) {
            result.status.store(status, Ordering::Relaxed);
            result.state.store(state as u32, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;

    use super::*;
    use crate::rendezvous::{MailboxState, MailboxValidation, RendezvousOperation};
    use crate::topology::CpuId;

    #[derive(Default)]
    struct ModelBackend {
        log: Vec<(u16, SwitchStep, u64)>,
        fail_at: Option<usize>,
    }

    impl ViewSwitchBackend for ModelBackend {
        fn run(&mut self, cpu: u16, step: SwitchStep, eptp: u64) -> MonadResult<()> {
            let ordinal = self.log.len();
            self.log.push((cpu, step, eptp));
            if self.fail_at == Some(ordinal) {
                return Err(MonadError::new(
                    ErrorPhase::Activation,
                    ErrorCode::InveptFailure,
                    ordinal as u64,
                ));
            }
            Ok(())
        }
    }

    fn view(slot: u16, eptp: u64) -> ActiveViewState {
        ActiveViewState {
            id: ViewId {
                slot,
                reserved: 0,
                generation: 1,
            },
            eptp,
        }
    }

    fn request(epoch: u64, old: ActiveViewState, new: ActiveViewState) -> MailboxRequest {
        MailboxRequest {
            epoch,
            operation: RendezvousOperation::SwitchView,
            target_view: new.id,
            target_eptp: new.eptp,
            expected_old_eptp: old.eptp,
        }
    }

    fn cpu(index: u16) -> CpuId {
        CpuId {
            dense_index: index,
            group: 0,
            number: index as u8,
            reserved: [0; 3],
        }
    }

    #[test]
    fn mailbox_transition_table() {
        let mailbox = InternalMailbox::new();
        let old = view(0, 0x1000);
        let new = view(1, 0x2000);
        let prepared = request(7, old, new);
        assert_eq!(mailbox.state(), Some(MailboxState::Idle));
        mailbox.prepare(prepared).expect("prepare");
        assert!(mailbox.prepare(prepared).is_err());
        let valid = MailboxValidation {
            cs_selector: 0,
            expected_cpu: cpu(0),
            current_cpu: cpu(0),
            active_epoch: 7,
            active_view: old.id,
            active_eptp: old.eptp,
            resolved_target_eptp: Some(new.eptp),
        };
        assert_eq!(mailbox.consume(valid).expect("consume"), prepared);
        mailbox.complete().expect("complete");
        mailbox.reset().expect("reset");
        for status in [
            MailboxStatus::WrongCpl,
            MailboxStatus::WrongCpu,
            MailboxStatus::WrongEpoch,
            MailboxStatus::OldViewMismatch,
            MailboxStatus::UnknownView,
            MailboxStatus::TargetEptpMismatch,
        ] {
            mailbox.prepare(prepared).expect("prepare");
            let mut invalid = valid;
            match status {
                MailboxStatus::WrongCpl => invalid.cs_selector = 3,
                MailboxStatus::WrongCpu => invalid.current_cpu = cpu(1),
                MailboxStatus::WrongEpoch => invalid.active_epoch = 8,
                MailboxStatus::OldViewMismatch => invalid.active_eptp = 0x3000,
                MailboxStatus::UnknownView => invalid.resolved_target_eptp = None,
                MailboxStatus::TargetEptpMismatch => invalid.resolved_target_eptp = Some(0x4000),
                _ => {}
            }
            assert_eq!(mailbox.consume(invalid), Err(status));
            if mailbox.state() == Some(MailboxState::Prepared) {
                mailbox.fail(status);
            }
            mailbox.reset().expect("reset");
        }
        mailbox.prepare(prepared).expect("prepare");
        mailbox.set_raw_operation(99);
        assert_eq!(mailbox.consume(valid), Err(MailboxStatus::InvalidOperation));
    }

    #[test]
    fn shared_base_eptp() {
        let base = view(0, 0x1234_501e);
        let states = [base; 256];
        assert!(states
            .iter()
            .all(|state| state.id == base.id && state.eptp == base.eptp));
    }

    #[test]
    fn transaction_success() {
        for count in [1u16, 2, 64, 256] {
            let targets: Vec<u16> = (0..count).filter(|cpu| cpu % 2 == 0).collect();
            let transaction = RendezvousTransaction::new(1, count, &targets, 100).expect("tx");
            let old = view(0, 0x1000);
            let new = view(1, 0x2000);
            for cpu in 0..count {
                if !transaction.is_target(cpu) {
                    transaction.set_result(cpu, CpuResultState::NotTarget, 0);
                    continue;
                }
                let mailbox = InternalMailbox::new();
                mailbox.prepare(request(1, old, new)).expect("prepare");
                let consumed = mailbox
                    .consume(MailboxValidation {
                        cs_selector: 0,
                        expected_cpu: super::tests::cpu(cpu),
                        current_cpu: super::tests::cpu(cpu),
                        active_epoch: 1,
                        active_view: old.id,
                        active_eptp: old.eptp,
                        resolved_target_eptp: Some(new.eptp),
                    })
                    .expect("consume");
                let mut active = old;
                let mut backend = ModelBackend::default();
                switch_view(cpu, &mut active, consumed, &mailbox, &mut backend).expect("switch");
                assert_eq!(active, new);
                assert_eq!(
                    backend.log.iter().map(|entry| entry.1).collect::<Vec<_>>(),
                    vec![
                        SwitchStep::WriteTarget,
                        SwitchStep::InvalidateOld,
                        SwitchStep::InvalidateTarget
                    ]
                );
                transaction.set_result(cpu, CpuResultState::Switched, 0);
            }
        }
    }

    #[test]
    fn failure_each_switch_step_rolls_back() {
        let old = view(0, 0x1000);
        let new = view(1, 0x2000);
        for fail_at in 0..3usize {
            let mailbox = InternalMailbox::new();
            mailbox.prepare(request(1, old, new)).expect("prepare");
            let consumed = mailbox
                .consume(MailboxValidation {
                    cs_selector: 0,
                    expected_cpu: cpu(0),
                    current_cpu: cpu(0),
                    active_epoch: 1,
                    active_view: old.id,
                    active_eptp: old.eptp,
                    resolved_target_eptp: Some(new.eptp),
                })
                .expect("consume");
            let mut active = old;
            let mut backend = ModelBackend {
                log: Vec::new(),
                fail_at: Some(fail_at),
            };
            assert!(switch_view(0, &mut active, consumed, &mailbox, &mut backend).is_err());
            assert_eq!(active, old);
            assert!(backend
                .log
                .iter()
                .any(|entry| entry.1 == SwitchStep::RestoreOld));
        }
    }

    #[test]
    fn illustrative_rollback_failure_model() {
        let transaction = RendezvousTransaction::new(1, 2, &[0, 1], 100).expect("tx");
        let mut active = view(1, 0x2000);
        let mut backend = ModelBackend {
            log: Vec::new(),
            fail_at: Some(0),
        };
        if rollback_view(0, &mut active, view(0, 0x1000), &mut backend).is_err() {
            transaction.fatal.store(true, Ordering::Release);
        }
        assert!(transaction.fatal.load(Ordering::Acquire));
        assert_eq!(active, view(1, 0x2000));
    }

    #[test]
    fn barrier_timeout_is_fatal() {
        let transaction = RendezvousTransaction::new(1, 3, &[0], 5).expect("tx");
        transaction.arrived.store(2, Ordering::Release);
        let mut tsc = 0u64;
        assert!(!transaction.wait_for(&transaction.arrived, || {
            tsc += 1;
            tsc
        }));
        assert!(transaction.fatal.load(Ordering::Acquire));
    }

    #[test]
    fn nontargets_remain_at_barrier() {
        let transaction = RendezvousTransaction::new(1, 3, &[0], 100).expect("tx");
        transaction.arrived.store(3, Ordering::Release);
        transaction.finished.store(2, Ordering::Release);
        let mut tsc = 0;
        assert!(!transaction.wait_for(&transaction.finished, || {
            tsc += 50;
            tsc
        }));
        assert_eq!(
            transaction.per_cpu[1].state(),
            CpuResultState::Waiting as u32
        );
    }

    #[test]
    fn no_active_table_write() {
        let old = view(0, 0x1000);
        let new = view(1, 0x2000);
        let mut active = old;
        let mailbox = InternalMailbox::new();
        mailbox.prepare(request(1, old, new)).expect("prepare");
        let consumed = mailbox
            .consume(MailboxValidation {
                cs_selector: 0,
                expected_cpu: cpu(0),
                current_cpu: cpu(0),
                active_epoch: 1,
                active_view: old.id,
                active_eptp: old.eptp,
                resolved_target_eptp: Some(new.eptp),
            })
            .expect("consume");
        let mut backend = ModelBackend::default();
        switch_view(0, &mut active, consumed, &mailbox, &mut backend).expect("switch");
        assert!(backend.log.iter().all(|entry| matches!(
            entry.1,
            SwitchStep::WriteTarget | SwitchStep::InvalidateOld | SwitchStep::InvalidateTarget
        )));
    }

    #[test]
    fn interleaving_model() {
        use std::collections::HashSet;

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        enum CpuModel {
            Native,
            WaitingOld,
            SwitchedNew,
            FailedOld,
            RolledBackOld,
            ReleasedOld,
            ReleasedNew,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        enum Phase {
            Arriving,
            Switching,
            RollingBack,
            ReleaseOld,
            ReleaseNew,
            Complete,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        struct Model {
            cpus: [CpuModel; 3],
            phase: Phase,
        }

        fn successors(model: Model, failed_cpu: Option<usize>) -> Vec<Model> {
            let mut next = Vec::new();
            match model.phase {
                Phase::Arriving => {
                    for cpu in 0..model.cpus.len() {
                        if model.cpus[cpu] == CpuModel::Native {
                            let mut state = model;
                            state.cpus[cpu] = CpuModel::WaitingOld;
                            next.push(state);
                        }
                    }
                    if model.cpus.iter().all(|cpu| *cpu == CpuModel::WaitingOld) {
                        let mut state = model;
                        state.phase = Phase::Switching;
                        next.push(state);
                    }
                }
                Phase::Switching => {
                    for cpu in 0..model.cpus.len() {
                        if model.cpus[cpu] == CpuModel::WaitingOld {
                            let mut state = model;
                            state.cpus[cpu] = if failed_cpu == Some(cpu) {
                                CpuModel::FailedOld
                            } else {
                                CpuModel::SwitchedNew
                            };
                            next.push(state);
                        }
                    }
                    if model
                        .cpus
                        .iter()
                        .all(|cpu| matches!(cpu, CpuModel::SwitchedNew | CpuModel::FailedOld))
                    {
                        let mut state = model;
                        state.phase = if model.cpus.contains(&CpuModel::FailedOld) {
                            Phase::RollingBack
                        } else {
                            Phase::ReleaseNew
                        };
                        next.push(state);
                    }
                }
                Phase::RollingBack => {
                    for cpu in 0..model.cpus.len() {
                        if model.cpus[cpu] == CpuModel::SwitchedNew {
                            let mut state = model;
                            state.cpus[cpu] = CpuModel::RolledBackOld;
                            next.push(state);
                        }
                    }
                    if !model.cpus.contains(&CpuModel::SwitchedNew) {
                        let mut state = model;
                        state.phase = Phase::ReleaseOld;
                        next.push(state);
                    }
                }
                Phase::ReleaseOld => {
                    for cpu in 0..model.cpus.len() {
                        if matches!(
                            model.cpus[cpu],
                            CpuModel::FailedOld | CpuModel::RolledBackOld
                        ) {
                            let mut state = model;
                            state.cpus[cpu] = CpuModel::ReleasedOld;
                            next.push(state);
                        }
                    }
                    if model.cpus.iter().all(|cpu| *cpu == CpuModel::ReleasedOld) {
                        let mut state = model;
                        state.phase = Phase::Complete;
                        next.push(state);
                    }
                }
                Phase::ReleaseNew => {
                    for cpu in 0..model.cpus.len() {
                        if model.cpus[cpu] == CpuModel::SwitchedNew {
                            let mut state = model;
                            state.cpus[cpu] = CpuModel::ReleasedNew;
                            next.push(state);
                        }
                    }
                    if model.cpus.iter().all(|cpu| *cpu == CpuModel::ReleasedNew) {
                        let mut state = model;
                        state.phase = Phase::Complete;
                        next.push(state);
                    }
                }
                Phase::Complete => {}
            }
            next
        }

        for failed_cpu in [None, Some(0usize), Some(1), Some(2)] {
            let initial = Model {
                cpus: [CpuModel::Native; 3],
                phase: Phase::Arriving,
            };
            let mut pending = vec![initial];
            let mut visited = HashSet::new();
            let mut completed = 0usize;
            while let Some(model) = pending.pop() {
                if !visited.insert(model) {
                    continue;
                }

                let released_old = model.cpus.contains(&CpuModel::ReleasedOld);
                let released_new = model.cpus.contains(&CpuModel::ReleasedNew);
                assert!(!(released_old && released_new), "mixed release: {model:?}");
                if released_old {
                    assert!(
                        !model.cpus.iter().any(|cpu| {
                            matches!(cpu, CpuModel::SwitchedNew | CpuModel::ReleasedNew)
                        }),
                        "old release while a CPU still has the new EPTP: {model:?}"
                    );
                }
                if released_new {
                    assert!(
                        model.cpus.iter().all(|cpu| {
                            matches!(cpu, CpuModel::SwitchedNew | CpuModel::ReleasedNew)
                        }),
                        "new release before every CPU switched: {model:?}"
                    );
                }
                if matches!(model.phase, Phase::Switching) {
                    assert!(
                        model.cpus.iter().all(|cpu| *cpu != CpuModel::Native),
                        "switching began before the arrival barrier: {model:?}"
                    );
                }

                if model.phase == Phase::Complete {
                    completed += 1;
                    if failed_cpu.is_some() {
                        assert_eq!(model.cpus, [CpuModel::ReleasedOld; 3]);
                    } else {
                        assert_eq!(model.cpus, [CpuModel::ReleasedNew; 3]);
                    }
                } else {
                    let next = successors(model, failed_cpu);
                    assert!(!next.is_empty(), "deadlocked model state: {model:?}");
                    pending.extend(next);
                }
            }
            assert!(
                completed > 0,
                "no terminal state for failure {failed_cpu:?}"
            );
        }
    }
    #[test]
    fn recovery_failure_cannot_cross_the_production_resume_boundary() {
        use crate::exit::{
            disposition::{ExitDisposition, FatalReason},
            vmcall::switch_disposition,
        };
        struct Hardware {
            eptp: u64,
            fail_forward: SwitchStep,
            fail_recovery: Option<SwitchStep>,
            invalidated: Vec<u64>,
        }
        impl ViewSwitchBackend for Hardware {
            fn run(&mut self, cpu: u16, step: SwitchStep, eptp: u64) -> MonadResult<()> {
                if step == self.fail_forward || Some(step) == self.fail_recovery {
                    return Err(MonadError::new(
                        ErrorPhase::Activation,
                        ErrorCode::InveptFailure,
                        step as u64,
                    )
                    .on_cpu(cpu));
                }
                match step {
                    SwitchStep::WriteTarget | SwitchStep::RestoreOld => self.eptp = eptp,
                    _ => self.invalidated.push(eptp),
                }
                Ok(())
            }
        }
        for forward in [
            SwitchStep::WriteTarget,
            SwitchStep::InvalidateOld,
            SwitchStep::InvalidateTarget,
        ] {
            for recovery in [
                None,
                Some(SwitchStep::RestoreOld),
                Some(SwitchStep::InvalidateFailedTarget),
                Some(SwitchStep::InvalidateRestoredOld),
            ] {
                let old = view(0, 0x101e);
                let target = view(1, 0x201e);
                let mut active = old;
                let mailbox = InternalMailbox::new();
                let mut hardware = Hardware {
                    eptp: old.eptp,
                    fail_forward: forward,
                    fail_recovery: recovery,
                    invalidated: Vec::new(),
                };
                let result = switch_view(
                    0,
                    &mut active,
                    request(1, old, target),
                    &mailbox,
                    &mut hardware,
                );
                let failure = result.expect_err("injected failure");
                assert_eq!(failure.forward.detail, forward as u64);
                assert_eq!(
                    failure.recovery.map(|error| error.detail),
                    recovery.map(|step| step as u64)
                );
                assert_eq!(active, old);
                let disposition = switch_disposition(RendezvousOperation::SwitchView, result);
                if recovery.is_some() {
                    assert_eq!(
                        disposition,
                        ExitDisposition::Fatal(FatalReason::RendezvousRollbackFailure)
                    );
                    if recovery == Some(SwitchStep::RestoreOld)
                        && forward != SwitchStep::WriteTarget
                    {
                        assert_eq!(hardware.eptp, target.eptp);
                    }
                } else {
                    assert_eq!(hardware.eptp, old.eptp);
                    assert!(hardware.invalidated.ends_with(&[target.eptp, old.eptp]));
                    assert_eq!(disposition, ExitDisposition::ResumeAndAdvance);
                }
            }
        }
    }

    #[test]
    fn mailbox_commit_failure_is_terminal_after_hardware_commit() {
        let old = view(0, 0x101e);
        let target = view(1, 0x201e);
        let mut active = old;
        let result = switch_view(
            0,
            &mut active,
            request(1, old, target),
            &InternalMailbox::new(),
            &mut ModelBackend::default(),
        );
        assert_eq!(active, target);
        assert!(result.expect_err("unarmed mailbox").recovery.is_some());
    }
}
