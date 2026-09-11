use crate::ept::ViewId;
use crate::exit::context::ExitContext;
use crate::topology::CpuId;

pub const EVENT_RECORD_BYTES: usize = 128;
pub const EVENT_SCHEMA_VERSION: u16 = 2;
pub const EVENT_PROVENANCE_VALID: u32 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    VmmLaunch = 1,
    LaunchFailure = 2,
    ViewSwitch = 3,
    ViewSwitchRollback = 4,
    EptViolation = 5,
    MalformedInternalVmcall = 6,
    UnexpectedVmcall = 7,
    UnexpectedVmExit = 8,
    MtrrModificationAttempt = 9,
    RepeatedEptFault = 10,
    Fatal = 11,
    ShutdownEntry = 12,
    VmxoffCompletion = 13,
}

#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventRecord {
    pub sequence: u64,
    pub tsc: u64,
    pub cpu_dense_index: u16,
    pub cpu_group: u16,
    pub cpu_number: u8,
    pub kind: u8,
    pub access: u8,
    pub reserved0: u8,
    pub view_slot: u16,
    pub reserved1: u16,
    pub view_generation: u64,
    pub guest_rip: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub qualification: u64,
    pub guest_physical_address: u64,
    pub guest_linear_address: u64,
    pub status: u32,
    pub detail: u32,
    pub schema_version: u16,
    pub record_size: u16,
    pub provenance_flags: u32,
    pub view_epoch: u64,
    pub run_id: u64,
    pub attempt_epoch: u64,
}

const _: [(); EVENT_RECORD_BYTES] = [(); core::mem::size_of::<EventRecord>()];
const _: [(); 64] = [(); core::mem::align_of::<EventRecord>()];

impl EventRecord {
    pub const fn zeroed() -> Self {
        Self {
            sequence: 0,
            tsc: 0,
            cpu_dense_index: 0,
            cpu_group: 0,
            cpu_number: 0,
            kind: 0,
            access: 0,
            reserved0: 0,
            view_slot: 0,
            reserved1: 0,
            view_generation: 0,
            guest_rip: 0,
            guest_rsp: 0,
            guest_rflags: 0,
            qualification: 0,
            guest_physical_address: 0,
            guest_linear_address: 0,
            status: 0,
            detail: 0,
            schema_version: 0,
            record_size: 0,
            provenance_flags: 0,
            view_epoch: 0,
            run_id: 0,
            attempt_epoch: 0,
        }
    }

    pub fn from_exit(
        context: &ExitContext,
        kind: EventKind,
        access: u8,
        status: u32,
        detail: u32,
    ) -> Self {
        Self {
            sequence: 0,
            tsc: context.tsc,
            cpu_dense_index: context.cpu.dense_index,
            cpu_group: context.cpu.group,
            cpu_number: context.cpu.number,
            kind: kind as u8,
            access,
            reserved0: 0,
            view_slot: context.active_view.slot,
            reserved1: 0,
            view_generation: context.active_view.generation,
            guest_rip: context.guest_rip,
            guest_rsp: context.guest_rsp,
            guest_rflags: context.guest_rflags,
            qualification: context.qualification.unwrap_or(0),
            guest_physical_address: context.guest_physical_address.unwrap_or(0),
            guest_linear_address: context.guest_linear_address.unwrap_or(0),
            status,
            detail,
            schema_version: EVENT_SCHEMA_VERSION,
            record_size: EVENT_RECORD_BYTES as u16,
            provenance_flags: 0,
            view_epoch: 0,
            run_id: 0,
            attempt_epoch: 0,
        }
    }

    pub const fn with_provenance(
        mut self,
        run_id: u64,
        view_epoch: u64,
        attempt_epoch: u64,
    ) -> Self {
        self.provenance_flags |= EVENT_PROVENANCE_VALID;
        self.view_epoch = view_epoch;
        self.run_id = run_id;
        self.attempt_epoch = attempt_epoch;
        self
    }

    pub fn encode_words(self) -> [u64; EVENT_RECORD_BYTES / 8] {
        let mut words = [0u64; EVENT_RECORD_BYTES / 8];
        words[0] = self.sequence;
        words[1] = self.tsc;
        words[2] = u64::from(self.cpu_dense_index)
            | (u64::from(self.cpu_group) << 16)
            | (u64::from(self.cpu_number) << 32)
            | (u64::from(self.kind) << 40)
            | (u64::from(self.access) << 48)
            | (u64::from(self.reserved0) << 56);
        words[3] = u64::from(self.view_slot) | (u64::from(self.reserved1) << 16);
        words[4] = self.view_generation;
        words[5] = self.guest_rip;
        words[6] = self.guest_rsp;
        words[7] = self.guest_rflags;
        words[8] = self.qualification;
        words[9] = self.guest_physical_address;
        words[10] = self.guest_linear_address;
        words[11] = u64::from(self.status) | (u64::from(self.detail) << 32);
        words[12] = u64::from(self.schema_version)
            | (u64::from(self.record_size) << 16)
            | (u64::from(self.provenance_flags) << 32);
        words[13] = self.view_epoch;
        words[14] = self.run_id;
        words[15] = self.attempt_epoch;
        words
    }

    pub fn decode_words(words: [u64; EVENT_RECORD_BYTES / 8]) -> Self {
        Self {
            sequence: words[0],
            tsc: words[1],
            cpu_dense_index: words[2] as u16,
            cpu_group: (words[2] >> 16) as u16,
            cpu_number: (words[2] >> 32) as u8,
            kind: (words[2] >> 40) as u8,
            access: (words[2] >> 48) as u8,
            reserved0: (words[2] >> 56) as u8,
            view_slot: words[3] as u16,
            reserved1: (words[3] >> 16) as u16,
            view_generation: words[4],
            guest_rip: words[5],
            guest_rsp: words[6],
            guest_rflags: words[7],
            qualification: words[8],
            guest_physical_address: words[9],
            guest_linear_address: words[10],
            status: words[11] as u32,
            detail: (words[11] >> 32) as u32,
            schema_version: words[12] as u16,
            record_size: (words[12] >> 16) as u16,
            provenance_flags: (words[12] >> 32) as u32,
            view_epoch: words[13],
            run_id: words[14],
            attempt_epoch: words[15],
        }
    }

    pub fn cpu(&self) -> CpuId {
        CpuId {
            dense_index: self.cpu_dense_index,
            group: self.cpu_group,
            number: self.cpu_number,
            reserved: [0; 3],
        }
    }

    pub fn view(&self) -> ViewId {
        ViewId {
            slot: self.view_slot,
            reserved: 0,
            generation: self.view_generation,
        }
    }

    pub fn encoded_reserved_is_zero(self) -> bool {
        let words = self.encode_words();
        self.reserved0 == 0 && self.reserved1 == 0 && words[3] >> 32 == 0
    }
}

impl Default for EventRecord {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_record_layout_and_zero_reserved() {
        assert_eq!(core::mem::size_of::<EventRecord>(), EVENT_RECORD_BYTES);
        assert_eq!(core::mem::align_of::<EventRecord>(), 64);
        let mut record = EventRecord::zeroed();
        record.sequence = 7;
        record.kind = EventKind::EptViolation as u8;
        record.schema_version = EVENT_SCHEMA_VERSION;
        record.record_size = EVENT_RECORD_BYTES as u16;
        record = record.with_provenance(0x1234, 9, 13);
        let decoded = EventRecord::decode_words(record.encode_words());
        assert_eq!(decoded, record);
        assert_eq!(decoded.run_id, 0x1234);
        assert_eq!(decoded.view_epoch, 9);
        assert_eq!(decoded.provenance_flags, EVENT_PROVENANCE_VALID);
        assert!(decoded.encoded_reserved_is_zero());
    }
}
