use wdk_sys::{
    ntddk::{KeGetProcessorNumberFromIndex, KeQueryActiveProcessorCountEx},
    PROCESSOR_NUMBER,
};

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

pub const MAX_LOGICAL_CPUS: usize = 256;
const ALL_PROCESSOR_GROUPS: u16 = u16::MAX;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuId {
    pub dense_index: u16,
    pub group: u16,
    pub number: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuSetWord {
    pub group: u16,
    pub reserved: u16,
    pub mask: u64,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuSetErrorDetail {
    Empty = 1,
    DuplicateGroup = 2,
    AbsentGroup = 3,
    InactiveBit = 4,
    ReservedNonzero = 5,
    CpuNotVirtualized = 6,
    InvalidDenseIndex = 7,
    DuplicateProcessor = 8,
    InvalidProcessorNumber = 9,
}

fn topology_error(code: ErrorCode, detail: u64) -> MonadError {
    MonadError::new(ErrorPhase::Topology, code, detail)
}

#[derive(Clone, Copy)]
pub struct CpuTopology {
    cpus: [CpuId; MAX_LOGICAL_CPUS],
    count: u16,
}

impl CpuTopology {
    pub fn from_ids(ids: &[CpuId]) -> MonadResult<Self> {
        if ids.len() > MAX_LOGICAL_CPUS {
            return Err(topology_error(
                ErrorCode::TooManyProcessors,
                ids.len() as u64,
            ));
        }
        if ids.is_empty() {
            return Err(topology_error(
                ErrorCode::InvalidCpuSet,
                CpuSetErrorDetail::Empty as u64,
            ));
        }

        let mut cpus = [CpuId::default(); MAX_LOGICAL_CPUS];
        for (index, id) in ids.iter().copied().enumerate() {
            if id.number >= 64 {
                return Err(topology_error(
                    ErrorCode::InvalidCpuSet,
                    CpuSetErrorDetail::InvalidProcessorNumber as u64,
                ));
            }
            if id.dense_index as usize != index || id.reserved != [0; 3] {
                return Err(topology_error(
                    ErrorCode::InvalidCpuSet,
                    CpuSetErrorDetail::InvalidDenseIndex as u64,
                ));
            }
            if ids[..index]
                .iter()
                .any(|prior| prior.group == id.group && prior.number == id.number)
            {
                return Err(topology_error(
                    ErrorCode::InvalidCpuSet,
                    CpuSetErrorDetail::DuplicateProcessor as u64,
                ));
            }
            cpus[index] = id;
        }
        Ok(Self {
            cpus,
            count: ids.len() as u16,
        })
    }

    pub const fn len(&self) -> u16 {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn ids(&self) -> &[CpuId] {
        &self.cpus[..usize::from(self.count)]
    }

    pub fn get(&self, dense_index: u16) -> Option<CpuId> {
        self.ids().get(usize::from(dense_index)).copied()
    }

    pub fn same_identity(&self, other: &Self) -> bool {
        self.ids() == other.ids()
    }

    pub fn validate_cpu_set(
        &self,
        words: &[CpuSetWord],
        virtualized: &[bool],
    ) -> MonadResult<CpuSelection> {
        if words.is_empty() {
            return Err(topology_error(
                ErrorCode::InvalidCpuSet,
                CpuSetErrorDetail::Empty as u64,
            ));
        }
        if virtualized.len() < usize::from(self.count) {
            return Err(topology_error(
                ErrorCode::InvalidCpuSet,
                CpuSetErrorDetail::CpuNotVirtualized as u64,
            ));
        }

        let mut selected = [false; MAX_LOGICAL_CPUS];
        let mut selected_count = 0u16;
        for (word_index, word) in words.iter().enumerate() {
            if word.reserved != 0 {
                return Err(topology_error(
                    ErrorCode::InvalidCpuSet,
                    CpuSetErrorDetail::ReservedNonzero as u64,
                )
                .at_operation(word_index as u32));
            }
            if words[..word_index]
                .iter()
                .any(|prior| prior.group == word.group)
            {
                return Err(topology_error(
                    ErrorCode::InvalidCpuSet,
                    CpuSetErrorDetail::DuplicateGroup as u64,
                )
                .at_operation(word_index as u32));
            }

            let group_mask = self
                .ids()
                .iter()
                .filter(|cpu| cpu.group == word.group)
                .fold(0u64, |mask, cpu| mask | (1u64 << cpu.number));
            if group_mask == 0 {
                return Err(topology_error(
                    ErrorCode::InvalidCpuSet,
                    CpuSetErrorDetail::AbsentGroup as u64,
                )
                .at_operation(word_index as u32));
            }
            if word.mask & !group_mask != 0 {
                return Err(topology_error(
                    ErrorCode::InvalidCpuSet,
                    CpuSetErrorDetail::InactiveBit as u64,
                )
                .at_operation(word_index as u32));
            }

            for cpu in self.ids().iter().filter(|cpu| cpu.group == word.group) {
                if word.mask & (1u64 << cpu.number) == 0 {
                    continue;
                }
                let dense = usize::from(cpu.dense_index);
                if !virtualized[dense] {
                    return Err(topology_error(
                        ErrorCode::InvalidCpuSet,
                        CpuSetErrorDetail::CpuNotVirtualized as u64,
                    )
                    .on_cpu(cpu.dense_index)
                    .at_operation(word_index as u32));
                }
                if !selected[dense] {
                    selected[dense] = true;
                    selected_count += 1;
                }
            }
        }

        if selected_count == 0 {
            return Err(topology_error(
                ErrorCode::InvalidCpuSet,
                CpuSetErrorDetail::Empty as u64,
            ));
        }
        Ok(CpuSelection {
            selected,
            count: selected_count,
        })
    }
}

pub struct CpuSelection {
    selected: [bool; MAX_LOGICAL_CPUS],
    count: u16,
}

impl CpuSelection {
    pub const fn len(&self) -> u16 {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn contains(&self, dense_index: u16) -> bool {
        self.selected
            .get(usize::from(dense_index))
            .copied()
            .unwrap_or(false)
    }
}

/// Captures active Windows processors in stable dense order.
///
/// This does no VMX work and runs before any processor enters VMXON.
pub fn snapshot_active_processors() -> MonadResult<CpuTopology> {
    // SAFETY: the group value is the documented all-groups sentinel and the
    // Routine has no pointer arguments.
    let count = unsafe { KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) };
    if count == 0 {
        return Err(topology_error(
            ErrorCode::InvalidCpuSet,
            CpuSetErrorDetail::Empty as u64,
        ));
    }
    if count as usize > MAX_LOGICAL_CPUS {
        return Err(topology_error(
            ErrorCode::TooManyProcessors,
            u64::from(count),
        ));
    }

    let mut ids = [CpuId::default(); MAX_LOGICAL_CPUS];
    for dense in 0..count {
        let mut native = PROCESSOR_NUMBER::default();
        // SAFETY: `native` is writable and `dense < count` came
        // From the immediately preceding active-processor snapshot.
        let status = unsafe { KeGetProcessorNumberFromIndex(dense, &mut native) };
        if status < 0 {
            return Err(topology_error(ErrorCode::TopologyChanged, u64::from(dense)));
        }
        ids[dense as usize] = CpuId {
            dense_index: dense as u16,
            group: native.Group,
            number: native.Number,
            reserved: [0; 3],
        };
    }
    CpuTopology::from_ids(&ids[..count as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CpuTopology {
        CpuTopology::from_ids(&[
            CpuId {
                dense_index: 0,
                group: 0,
                number: 0,
                reserved: [0; 3],
            },
            CpuId {
                dense_index: 1,
                group: 0,
                number: 2,
                reserved: [0; 3],
            },
            CpuId {
                dense_index: 2,
                group: 3,
                number: 1,
                reserved: [0; 3],
            },
        ])
        .expect("valid topology fixture")
    }

    fn detail(result: MonadResult<CpuSelection>) -> u64 {
        match result {
            Ok(_) => panic!("fixture unexpectedly succeeded"),
            Err(error) => error.detail,
        }
    }

    #[test]
    fn cpu_set_validation() {
        let topology = fixture();
        let all_virtualized = [true, true, true];

        assert_eq!(
            detail(topology.validate_cpu_set(&[], &all_virtualized)),
            CpuSetErrorDetail::Empty as u64
        );
        assert_eq!(
            detail(topology.validate_cpu_set(
                &[
                    CpuSetWord {
                        group: 0,
                        reserved: 0,
                        mask: 1,
                    },
                    CpuSetWord {
                        group: 0,
                        reserved: 0,
                        mask: 4,
                    },
                ],
                &all_virtualized,
            )),
            CpuSetErrorDetail::DuplicateGroup as u64
        );
        assert_eq!(
            detail(topology.validate_cpu_set(
                &[CpuSetWord {
                    group: 9,
                    reserved: 0,
                    mask: 1,
                }],
                &all_virtualized,
            )),
            CpuSetErrorDetail::AbsentGroup as u64
        );
        assert_eq!(
            detail(topology.validate_cpu_set(
                &[CpuSetWord {
                    group: 0,
                    reserved: 0,
                    mask: 2,
                }],
                &all_virtualized,
            )),
            CpuSetErrorDetail::InactiveBit as u64
        );
        assert_eq!(
            detail(topology.validate_cpu_set(
                &[CpuSetWord {
                    group: 0,
                    reserved: 1,
                    mask: 1,
                }],
                &all_virtualized,
            )),
            CpuSetErrorDetail::ReservedNonzero as u64
        );
        assert_eq!(
            detail(topology.validate_cpu_set(
                &[CpuSetWord {
                    group: 3,
                    reserved: 0,
                    mask: 2,
                }],
                &[true, true, false],
            )),
            CpuSetErrorDetail::CpuNotVirtualized as u64
        );

        let selected = topology
            .validate_cpu_set(
                &[
                    CpuSetWord {
                        group: 0,
                        reserved: 0,
                        mask: 5,
                    },
                    CpuSetWord {
                        group: 3,
                        reserved: 0,
                        mask: 2,
                    },
                ],
                &all_virtualized,
            )
            .expect("valid multi-group set");
        assert_eq!(selected.len(), 3);
        assert!(selected.contains(0) && selected.contains(1) && selected.contains(2));
    }
}
