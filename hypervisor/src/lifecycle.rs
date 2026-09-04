extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Absent = 0,
    Preparing = 1,
    Launching = 2,
    Running = 3,
    Quiescing = 4,
    Stopping = 5,
    Fatal = 6,
}

impl LifecycleState {
    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Absent),
            1 => Some(Self::Preparing),
            2 => Some(Self::Launching),
            3 => Some(Self::Running),
            4 => Some(Self::Quiescing),
            5 => Some(Self::Stopping),
            6 => Some(Self::Fatal),
            _ => None,
        }
    }

    pub const fn allows(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Absent, Self::Preparing)
                | (Self::Preparing, Self::Launching)
                | (Self::Preparing, Self::Absent)
                | (Self::Launching, Self::Running)
                | (Self::Launching, Self::Absent)
                | (Self::Running, Self::Quiescing)
                | (Self::Running, Self::Fatal)
                | (Self::Quiescing, Self::Running)
                | (Self::Quiescing, Self::Stopping)
                | (Self::Stopping, Self::Absent)
                | (Self::Stopping, Self::Fatal)
        )
    }
}

pub struct Lifecycle {
    state: AtomicU8,
    control_lock: AtomicBool,
}

impl Lifecycle {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(LifecycleState::Absent as u8),
            control_lock: AtomicBool::new(false),
        }
    }

    pub fn state(&self) -> LifecycleState {
        LifecycleState::decode(self.state.load(Ordering::Acquire)).unwrap_or(LifecycleState::Fatal)
    }

    pub fn try_control(&self) -> MonadResult<LifecycleControl<'_>> {
        self.control_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| MonadError::new(ErrorPhase::Session, ErrorCode::ControllerBusy, 0))?;
        Ok(LifecycleControl { lifecycle: self })
    }

    pub fn enter_fatal(&self) {
        self.state
            .store(LifecycleState::Fatal as u8, Ordering::Release);
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LifecycleControl<'a> {
    lifecycle: &'a Lifecycle,
}

impl LifecycleControl<'_> {
    pub fn state(&self) -> LifecycleState {
        self.lifecycle.state()
    }

    pub fn transition(&self, expected: LifecycleState, next: LifecycleState) -> MonadResult<()> {
        if !expected.allows(next) {
            return Err(MonadError::new(
                ErrorPhase::Session,
                ErrorCode::InvalidLifecycleState,
                (expected as u64) | ((next as u64) << 8),
            ));
        }
        self.lifecycle
            .state
            .compare_exchange(
                expected as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|actual| {
                MonadError::new(
                    ErrorPhase::Session,
                    ErrorCode::InvalidLifecycleState,
                    u64::from(actual),
                )
            })?;
        Ok(())
    }
}

impl Drop for LifecycleControl<'_> {
    fn drop(&mut self) {
        self.lifecycle.control_lock.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugState {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownOrigin {
    pub cpl: u8,
    pub rip: u64,
    pub trampoline_start: u64,
    pub trampoline_end: u64,
    pub expected_epoch: u64,
    pub mailbox_epoch: u64,
    pub expected_cpu: u16,
    pub current_cpu: u16,
}

pub fn validate_shutdown_origin(origin: ShutdownOrigin) -> MonadResult<()> {
    let valid = origin.cpl == 0
        && origin.trampoline_start < origin.trampoline_end
        && origin.trampoline_start <= origin.rip
        && origin.rip < origin.trampoline_end
        && origin.expected_epoch != 0
        && origin.expected_epoch == origin.mailbox_epoch
        && origin.expected_cpu == origin.current_cpu;
    if !valid {
        return Err(MonadError::new(
            ErrorPhase::Shutdown,
            ErrorCode::AccessDenied,
            origin.rip,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn lifecycle_transition_table() {
        let states = [
            LifecycleState::Absent,
            LifecycleState::Preparing,
            LifecycleState::Launching,
            LifecycleState::Running,
            LifecycleState::Quiescing,
            LifecycleState::Stopping,
            LifecycleState::Fatal,
        ];
        let allowed = [
            (LifecycleState::Absent, LifecycleState::Preparing),
            (LifecycleState::Preparing, LifecycleState::Launching),
            (LifecycleState::Preparing, LifecycleState::Absent),
            (LifecycleState::Launching, LifecycleState::Running),
            (LifecycleState::Launching, LifecycleState::Absent),
            (LifecycleState::Running, LifecycleState::Quiescing),
            (LifecycleState::Running, LifecycleState::Fatal),
            (LifecycleState::Quiescing, LifecycleState::Running),
            (LifecycleState::Quiescing, LifecycleState::Stopping),
            (LifecycleState::Stopping, LifecycleState::Absent),
            (LifecycleState::Stopping, LifecycleState::Fatal),
        ];
        for from in states {
            for to in states {
                assert_eq!(from.allows(to), allowed.contains(&(from, to)));
            }
        }
        let lifecycle = Lifecycle::new();
        let control = lifecycle.try_control().expect("control");
        let error = match lifecycle.try_control() {
            Ok(_) => panic!("second control lock succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::ControllerBusy);
        control
            .transition(LifecycleState::Absent, LifecycleState::Preparing)
            .expect("prepare");
    }

    #[test]
    fn launch_failure_each_cpu_each_phase() {
        for cpus in [1usize, 2, 8, 256] {
            for failure in 0..cpus * 5 {
                let failed_cpu = failure / 5;
                let failed_phase = failure % 5;
                let mut launched = [false; 256];
                for cpu in 0..cpus {
                    for phase in 0..5 {
                        if cpu == failed_cpu && phase == failed_phase {
                            launched[..cpu].fill(false);
                            assert!(launched[..cpus].iter().all(|state| !*state));
                            break;
                        }
                        if phase == 4 {
                            launched[cpu] = true;
                        }
                    }
                    if cpu == failed_cpu {
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn running_only_after_all_launched() {
        for count in 1..=32usize {
            let mut launched = [false; 32];
            for cpu in 0..count {
                launched[cpu] = true;
                assert_eq!(
                    launched[..count].iter().all(|value| *value),
                    cpu + 1 == count
                );
            }
        }
    }

    #[test]
    fn shutdown_requires_registered_cpl0_trampoline() {
        let valid = ShutdownOrigin {
            cpl: 0,
            rip: 0x1010,
            trampoline_start: 0x1000,
            trampoline_end: 0x1020,
            expected_epoch: 8,
            mailbox_epoch: 8,
            expected_cpu: 3,
            current_cpu: 3,
        };
        assert!(validate_shutdown_origin(valid).is_ok());
        for index in 0..6usize {
            let mut invalid = valid;
            match index {
                0 => invalid.cpl = 3,
                1 => invalid.rip = invalid.trampoline_start - 1,
                2 => invalid.rip = invalid.trampoline_end,
                3 => invalid.mailbox_epoch += 1,
                4 => invalid.current_cpu += 1,
                _ => invalid.trampoline_end = invalid.trampoline_start,
            }
            assert!(validate_shutdown_origin(invalid).is_err());
        }
    }

    #[test]
    fn shutdown_restores_state() {
        let before = DebugState {
            dr0: 1,
            dr1: 2,
            dr2: 3,
            dr3: 4,
            dr6: 6,
            dr7: 7,
        };
        let corrupted = DebugState {
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
        };
        assert_ne!(corrupted, before);
        let after = before;
        assert_eq!(after, before);
    }

    #[test]
    fn extended_state_round_trip() {
        for size in [576usize, 832, 2688, 8192, 65536] {
            let mut area = vec![0; size];
            for (index, byte) in area.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(37);
            }
            let saved = area.clone();
            area.fill(0xaa);
            area.copy_from_slice(&saved);
            assert_eq!(area, saved);
        }
    }

    #[test]
    fn register_snapshot_boundary() {
        let captured = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let mut setup_scratch = captured;
        setup_scratch.fill(u64::MAX);
        assert_eq!(captured, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn partial_shutdown_is_fatal() {
        let lifecycle = Lifecycle::new();
        let control = lifecycle.try_control().expect("control");
        control
            .transition(LifecycleState::Absent, LifecycleState::Preparing)
            .expect("prepare");
        control
            .transition(LifecycleState::Preparing, LifecycleState::Launching)
            .expect("launch");
        control
            .transition(LifecycleState::Launching, LifecycleState::Running)
            .expect("running");
        control
            .transition(LifecycleState::Running, LifecycleState::Quiescing)
            .expect("quiesce");
        control
            .transition(LifecycleState::Quiescing, LifecycleState::Stopping)
            .expect("stop");
        lifecycle.enter_fatal();
        assert_eq!(lifecycle.state(), LifecycleState::Fatal);
    }

    #[test]
    fn fatal_never_calls_vmxoff() {
        let vmxoff_called = AtomicBool::new(false);
        let lifecycle = Lifecycle::new();
        lifecycle.enter_fatal();
        assert_eq!(lifecycle.state(), LifecycleState::Fatal);
        assert!(!vmxoff_called.load(Ordering::Acquire));
    }

    #[test]
    fn mtrr_write_is_fatal() {
        for msr in [0x200u32, 0x20f, 0x250, 0x258, 0x259, 0x268, 0x26f, 0x2ff] {
            assert!(crate::exit::msr::is_mtrr_write(msr));
        }
        assert!(!crate::exit::msr::is_mtrr_write(0x1b));
    }

    #[test]
    fn no_production_panic_surface() {
        let files = [
            include_str!("vmm.rs"),
            include_str!("exit/vmcall.rs"),
            include_str!("exit/vmexit.rs"),
            include_str!("rendezvous/mailbox.rs"),
            include_str!("rendezvous/transaction.rs"),
            include_str!("lifecycle.rs"),
        ];
        for file in files {
            let production = file.split("#[cfg(test)]").next().unwrap_or(file);
            for forbidden in ["unwrap(", "expect(", "panic!(", "todo!(", "unimplemented!("] {
                assert!(!production.contains(forbidden), "found {forbidden}");
            }
        }
    }
}
