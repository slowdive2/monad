use crate::ept::ViewId;
use crate::error::MonadResult;
use crate::topology::CpuId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextField {
    ExitReason,
    Qualification,
    InstructionLength,
    GuestRip,
    GuestRsp,
    GuestRflags,
    GuestCsSelector,
    GuestSsSelector,
    GuestCsAccess,
    GuestSsAccess,
    GuestCr0,
    GuestCr3,
    GuestCr4,
    GuestLinearAddress,
    GuestPhysicalAddress,
    ExitInterruptionInfo,
    IdtVectoringInfo,
    IdtVectoringErrorCode,
}

pub trait ContextReader {
    fn read(&mut self, field: ContextField) -> MonadResult<u64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitFieldValidity {
    pub qualification: bool,
    pub instruction_length: bool,
    pub guest_linear_address: bool,
    pub guest_physical_address: bool,
    pub exit_interruption_info: bool,
    pub idt_vectoring_info: bool,
    pub idt_vectoring_error_code: bool,
}

impl ExitFieldValidity {
    pub const fn for_basic_reason(reason: u16, qualification: u64) -> Self {
        let ept = reason == 48;
        Self {
            qualification: ept,
            instruction_length: matches!(reason, 10 | 18 | 31 | 32),
            guest_linear_address: ept && qualification & (1 << 7) != 0,
            guest_physical_address: matches!(reason, 48 | 49),
            exit_interruption_info: false,
            idt_vectoring_info: false,
            idt_vectoring_error_code: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitContext {
    pub basic_reason: u16,
    pub qualification: Option<u64>,
    pub instruction_length: Option<u32>,
    pub guest_rip: u64,
    pub guest_rsp: u64,
    pub guest_rflags: u64,
    pub guest_cs_selector: u16,
    pub guest_ss_selector: u16,
    pub guest_cs_access: u32,
    pub guest_ss_access: u32,
    pub guest_cr0: u64,
    pub guest_cr3: u64,
    pub guest_cr4: u64,
    pub guest_linear_address: Option<u64>,
    pub guest_physical_address: Option<u64>,
    pub exit_interruption_info: Option<u32>,
    pub idt_vectoring_info: Option<u32>,
    pub idt_vectoring_error_code: Option<u32>,
    pub cpu: CpuId,
    pub active_view: ViewId,
    pub tsc: u64,
}

pub fn capture_exit_context<R: ContextReader>(
    reader: &mut R,
    validity: ExitFieldValidity,
    cpu: CpuId,
    active_view: ViewId,
    tsc: u64,
) -> MonadResult<ExitContext> {
    Ok(ExitContext {
        basic_reason: reader.read(ContextField::ExitReason)? as u16,
        qualification: read_optional(reader, ContextField::Qualification, validity.qualification)?,
        instruction_length: read_optional(
            reader,
            ContextField::InstructionLength,
            validity.instruction_length,
        )?
        .map(|value| value as u32),
        guest_rip: reader.read(ContextField::GuestRip)?,
        guest_rsp: reader.read(ContextField::GuestRsp)?,
        guest_rflags: reader.read(ContextField::GuestRflags)?,
        guest_cs_selector: reader.read(ContextField::GuestCsSelector)? as u16,
        guest_ss_selector: reader.read(ContextField::GuestSsSelector)? as u16,
        guest_cs_access: reader.read(ContextField::GuestCsAccess)? as u32,
        guest_ss_access: reader.read(ContextField::GuestSsAccess)? as u32,
        guest_cr0: reader.read(ContextField::GuestCr0)?,
        guest_cr3: reader.read(ContextField::GuestCr3)?,
        guest_cr4: reader.read(ContextField::GuestCr4)?,
        guest_linear_address: read_optional(
            reader,
            ContextField::GuestLinearAddress,
            validity.guest_linear_address,
        )?,
        guest_physical_address: read_optional(
            reader,
            ContextField::GuestPhysicalAddress,
            validity.guest_physical_address,
        )?,
        exit_interruption_info: read_optional(
            reader,
            ContextField::ExitInterruptionInfo,
            validity.exit_interruption_info,
        )?
        .map(|value| value as u32),
        idt_vectoring_info: read_optional(
            reader,
            ContextField::IdtVectoringInfo,
            validity.idt_vectoring_info,
        )?
        .map(|value| value as u32),
        idt_vectoring_error_code: read_optional(
            reader,
            ContextField::IdtVectoringErrorCode,
            validity.idt_vectoring_error_code,
        )?
        .map(|value| value as u32),
        cpu,
        active_view,
        tsc,
    })
}

fn read_optional<R: ContextReader>(
    reader: &mut R,
    field: ContextField,
    valid: bool,
) -> MonadResult<Option<u64>> {
    if valid {
        reader.read(field).map(Some)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use crate::error::{ErrorCode, ErrorPhase, MonadError};

    use super::*;

    struct Spy {
        reads: Vec<ContextField>,
    }

    impl ContextReader for Spy {
        fn read(&mut self, field: ContextField) -> MonadResult<u64> {
            self.reads.push(field);
            Ok(match field {
                ContextField::ExitReason => 48,
                _ => field as u64 + 1,
            })
        }
    }

    fn cpu() -> CpuId {
        CpuId {
            dense_index: 1,
            group: 0,
            number: 1,
            reserved: [0; 3],
        }
    }

    fn view() -> ViewId {
        ViewId {
            slot: 0,
            reserved: 0,
            generation: 1,
        }
    }

    #[test]
    fn exit_context_validity() {
        for bits in 0u8..128 {
            let validity = ExitFieldValidity {
                qualification: bits & 1 != 0,
                instruction_length: bits & 2 != 0,
                guest_linear_address: bits & 4 != 0,
                guest_physical_address: bits & 8 != 0,
                exit_interruption_info: bits & 16 != 0,
                idt_vectoring_info: bits & 32 != 0,
                idt_vectoring_error_code: bits & 64 != 0,
            };
            let mut spy = Spy { reads: Vec::new() };
            let context =
                capture_exit_context(&mut spy, validity, cpu(), view(), 7).expect("context");
            for (field, valid) in [
                (ContextField::Qualification, validity.qualification),
                (ContextField::InstructionLength, validity.instruction_length),
                (
                    ContextField::GuestLinearAddress,
                    validity.guest_linear_address,
                ),
                (
                    ContextField::GuestPhysicalAddress,
                    validity.guest_physical_address,
                ),
                (
                    ContextField::ExitInterruptionInfo,
                    validity.exit_interruption_info,
                ),
                (ContextField::IdtVectoringInfo, validity.idt_vectoring_info),
                (
                    ContextField::IdtVectoringErrorCode,
                    validity.idt_vectoring_error_code,
                ),
            ] {
                assert_eq!(spy.reads.contains(&field), valid);
            }
            assert_eq!(context.qualification.is_some(), validity.qualification);
        }

        struct Failure;
        impl ContextReader for Failure {
            fn read(&mut self, _field: ContextField) -> MonadResult<u64> {
                Err(MonadError::new(
                    ErrorPhase::ExitHandling,
                    ErrorCode::VmreadFailure,
                    0,
                ))
            }
        }
        assert!(capture_exit_context(
            &mut Failure,
            ExitFieldValidity::for_basic_reason(48, 0),
            cpu(),
            view(),
            0
        )
        .is_err());
    }
}
