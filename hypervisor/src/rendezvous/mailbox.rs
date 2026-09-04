use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate::ept::{ViewId, MAX_PUBLISHED_VIEWS};
use crate::topology::CpuId;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxState {
    Idle = 0,
    Prepared = 1,
    Executing = 2,
    Completed = 3,
    Failed = 4,
}

impl MailboxState {
    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Idle),
            1 => Some(Self::Prepared),
            2 => Some(Self::Executing),
            3 => Some(Self::Completed),
            4 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousOperation {
    SwitchView = 1,
    RollbackView = 2,
    Shutdown = 3,
}

impl RendezvousOperation {
    fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SwitchView),
            2 => Some(Self::RollbackView),
            3 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxStatus {
    Pending = 0,
    Success = 1,
    WrongCpl = 2,
    WrongCpu = 3,
    WrongState = 4,
    WrongEpoch = 5,
    InvalidOperation = 6,
    OldViewMismatch = 7,
    UnknownView = 8,
    TargetEptpMismatch = 9,
    SwitchFailed = 10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxRequest {
    pub epoch: u64,
    pub operation: RendezvousOperation,
    pub target_view: ViewId,
    pub target_eptp: u64,
    pub expected_old_eptp: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct MailboxValidation {
    pub cs_selector: u16,
    pub expected_cpu: CpuId,
    pub current_cpu: CpuId,
    pub active_epoch: u64,
    pub active_view: ViewId,
    pub active_eptp: u64,
    pub resolved_target_eptp: Option<u64>,
}

pub struct InternalMailbox {
    state: AtomicU8,
    epoch: AtomicU64,
    operation: AtomicU8,
    target_eptp: AtomicU64,
    target_view_slot: AtomicU16,
    target_view_generation: AtomicU64,
    expected_old_eptp: AtomicU64,
    status: AtomicU32,
}

struct PublishedViewSlot {
    generation: AtomicU64,
    eptp: AtomicU64,
}

impl PublishedViewSlot {
    const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            eptp: AtomicU64::new(0),
        }
    }
}

pub struct PublishedViewDirectory {
    slots: [PublishedViewSlot; MAX_PUBLISHED_VIEWS],
}

impl PublishedViewDirectory {
    pub const fn new() -> Self {
        Self {
            slots: [const { PublishedViewSlot::new() }; MAX_PUBLISHED_VIEWS],
        }
    }

    pub fn publish(&self, id: ViewId, eptp: u64) -> Result<(), MailboxStatus> {
        if id.reserved != 0 || id.generation == 0 || eptp == 0 {
            return Err(MailboxStatus::UnknownView);
        }
        let slot = self
            .slots
            .get(usize::from(id.slot))
            .ok_or(MailboxStatus::UnknownView)?;
        if slot.generation.load(Ordering::Acquire) != 0 {
            return Err(MailboxStatus::WrongState);
        }
        slot.eptp.store(eptp, Ordering::Relaxed);
        slot.generation.store(id.generation, Ordering::Release);
        Ok(())
    }

    pub fn resolve(&self, id: ViewId) -> Option<u64> {
        if id.reserved != 0 || id.generation == 0 {
            return None;
        }
        let slot = self.slots.get(usize::from(id.slot))?;
        if slot.generation.load(Ordering::Acquire) != id.generation {
            return None;
        }
        Some(slot.eptp.load(Ordering::Relaxed))
    }
}

impl Default for PublishedViewDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl InternalMailbox {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(MailboxState::Idle as u8),
            epoch: AtomicU64::new(0),
            operation: AtomicU8::new(0),
            target_eptp: AtomicU64::new(0),
            target_view_slot: AtomicU16::new(0),
            target_view_generation: AtomicU64::new(0),
            expected_old_eptp: AtomicU64::new(0),
            status: AtomicU32::new(MailboxStatus::Pending as u32),
        }
    }

    pub fn state(&self) -> Option<MailboxState> {
        MailboxState::decode(self.state.load(Ordering::Acquire))
    }

    pub fn status(&self) -> u32 {
        self.status.load(Ordering::Acquire)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub(crate) fn prepared_target(&self) -> Option<ViewId> {
        if self.state.load(Ordering::Acquire) != MailboxState::Prepared as u8 {
            return None;
        }
        Some(ViewId {
            slot: self.target_view_slot.load(Ordering::Relaxed),
            reserved: 0,
            generation: self.target_view_generation.load(Ordering::Relaxed),
        })
    }

    pub fn prepare(&self, request: MailboxRequest) -> Result<(), MailboxStatus> {
        if self.state.load(Ordering::Acquire) != MailboxState::Idle as u8 {
            return Err(MailboxStatus::WrongState);
        }
        self.operation
            .store(request.operation as u8, Ordering::Relaxed);
        self.target_eptp
            .store(request.target_eptp, Ordering::Relaxed);
        self.target_view_slot
            .store(request.target_view.slot, Ordering::Relaxed);
        self.target_view_generation
            .store(request.target_view.generation, Ordering::Relaxed);
        self.expected_old_eptp
            .store(request.expected_old_eptp, Ordering::Relaxed);
        self.epoch.store(request.epoch, Ordering::Relaxed);
        self.status
            .store(MailboxStatus::Pending as u32, Ordering::Relaxed);
        self.state
            .store(MailboxState::Prepared as u8, Ordering::Release);
        Ok(())
    }

    fn reject(&self, status: MailboxStatus) -> Result<MailboxRequest, MailboxStatus> {
        self.status.store(status as u32, Ordering::Release);
        if self.state.load(Ordering::Acquire) == MailboxState::Executing as u8 {
            self.state
                .store(MailboxState::Failed as u8, Ordering::Release);
        }
        Err(status)
    }

    pub fn consume(&self, validation: MailboxValidation) -> Result<MailboxRequest, MailboxStatus> {
        if validation.cs_selector & 3 != 0 {
            return self.reject(MailboxStatus::WrongCpl);
        }
        if validation.current_cpu != validation.expected_cpu {
            return self.reject(MailboxStatus::WrongCpu);
        }
        if self
            .state
            .compare_exchange(
                MailboxState::Prepared as u8,
                MailboxState::Executing as u8,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return self.reject(MailboxStatus::WrongState);
        }
        let epoch = self.epoch.load(Ordering::Relaxed);
        if epoch == 0 || epoch != validation.active_epoch {
            return self.reject(MailboxStatus::WrongEpoch);
        }
        let Some(operation) = RendezvousOperation::decode(self.operation.load(Ordering::Relaxed))
        else {
            return self.reject(MailboxStatus::InvalidOperation);
        };
        let expected_old_eptp = self.expected_old_eptp.load(Ordering::Relaxed);
        if expected_old_eptp != validation.active_eptp {
            return self.reject(MailboxStatus::OldViewMismatch);
        }
        let target_view = ViewId {
            slot: self.target_view_slot.load(Ordering::Relaxed),
            reserved: 0,
            generation: self.target_view_generation.load(Ordering::Relaxed),
        };
        let target_eptp = self.target_eptp.load(Ordering::Relaxed);
        if operation != RendezvousOperation::Shutdown {
            let Some(resolved) = validation.resolved_target_eptp else {
                return self.reject(MailboxStatus::UnknownView);
            };
            if resolved != target_eptp || target_view.generation == 0 {
                return self.reject(MailboxStatus::TargetEptpMismatch);
            }
        }
        let _ = validation.active_view;
        Ok(MailboxRequest {
            epoch,
            operation,
            target_view,
            target_eptp,
            expected_old_eptp,
        })
    }

    pub fn complete(&self) -> Result<(), MailboxStatus> {
        if self
            .state
            .compare_exchange(
                MailboxState::Executing as u8,
                MailboxState::Completed as u8,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(MailboxStatus::WrongState);
        }
        self.status
            .store(MailboxStatus::Success as u32, Ordering::Release);
        Ok(())
    }

    pub fn fail(&self, status: MailboxStatus) {
        self.status.store(status as u32, Ordering::Release);
        self.state
            .store(MailboxState::Failed as u8, Ordering::Release);
    }

    pub fn reset(&self) -> Result<(), MailboxStatus> {
        let state = self.state.load(Ordering::Acquire);
        if state != MailboxState::Completed as u8 && state != MailboxState::Failed as u8 {
            return Err(MailboxStatus::WrongState);
        }
        self.status
            .store(MailboxStatus::Pending as u32, Ordering::Relaxed);
        self.state
            .store(MailboxState::Idle as u8, Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn set_raw_operation(&self, operation: u8) {
        self.operation.store(operation, Ordering::Relaxed);
    }
}

impl Default for InternalMailbox {
    fn default() -> Self {
        Self::new()
    }
}
