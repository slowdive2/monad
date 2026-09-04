use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlField {
    PinBased = 1,
    PrimaryProcessorBased = 2,
    SecondaryProcessorBased = 3,
    VmExit = 4,
    VmEntry = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlCapability {
    must_be_one: u32,
    may_be_one: u32,
}

impl ControlCapability {
    pub const fn from_msr(value: u64) -> Self {
        Self {
            must_be_one: value as u32,
            may_be_one: (value >> 32) as u32,
        }
    }

    pub const fn unrestricted() -> Self {
        Self {
            must_be_one: 0,
            may_be_one: u32::MAX,
        }
    }

    pub fn adjust(self, field: ControlField, requested: u32) -> MonadResult<u32> {
        let contradictory = self.must_be_one & !self.may_be_one;
        if contradictory != 0 {
            let detail = ((field as u64) << 32) | u64::from(contradictory);
            return Err(MonadError::new(
                ErrorPhase::Capability,
                ErrorCode::UnsupportedCapability,
                detail,
            ));
        }
        let adjusted = (requested | self.must_be_one) & self.may_be_one;
        let missing = requested & !adjusted;
        if missing != 0 {
            let detail = ((field as u64) << 32) | u64::from(missing);
            return Err(MonadError::new(
                ErrorPhase::Capability,
                ErrorCode::UnsupportedCapability,
                detail,
            ));
        }
        Ok(adjusted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmxControls {
    pub pinbased: u32,
    pub primary: u32,
    pub secondary: u32,
    pub vmexit: u32,
    pub vmentry: u32,
}

pub const REQUIRED_PINBASED: u32 = 0;
pub const REQUIRED_PRIMARY: u32 = (1 << 31) | (1 << 28);
pub const ENABLE_EPT: u32 = 1 << 1;
pub const ENABLE_RDTSCP: u32 = 1 << 3;
pub const ENABLE_INVPCID: u32 = 1 << 12;
pub const ENABLE_XSAVES_XRSTORS: u32 = 1 << 20;
pub const ENABLE_USER_WAIT_PAUSE: u32 = 1 << 26;
pub const REQUIRED_SECONDARY: u32 = ENABLE_EPT | ENABLE_XSAVES_XRSTORS;
pub const REQUIRED_VMEXIT: u32 = 1 << 9;
pub const REQUIRED_VMENTRY: u32 = 1 << 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlCapabilities {
    pub pinbased: ControlCapability,
    pub primary: ControlCapability,
    pub secondary: ControlCapability,
    pub vmexit: ControlCapability,
    pub vmentry: ControlCapability,
}

impl ControlCapabilities {
    pub fn required_controls(self) -> MonadResult<VmxControls> {
        self.controls_for(REQUIRED_SECONDARY)
    }

    pub fn controls_for(self, requested_secondary: u32) -> MonadResult<VmxControls> {
        Ok(VmxControls {
            pinbased: self
                .pinbased
                .adjust(ControlField::PinBased, REQUIRED_PINBASED)?,
            primary: self
                .primary
                .adjust(ControlField::PrimaryProcessorBased, REQUIRED_PRIMARY)?,
            secondary: self.secondary.adjust(
                ControlField::SecondaryProcessorBased,
                requested_secondary | REQUIRED_SECONDARY,
            )?,
            vmexit: self.vmexit.adjust(ControlField::VmExit, REQUIRED_VMEXIT)?,
            vmentry: self
                .vmentry
                .adjust(ControlField::VmEntry, REQUIRED_VMENTRY)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_adjustment_table() {
        let cases = [
            (0, u32::MAX, 0x5, Ok(0x5)),
            (0x8, u32::MAX, 0x1, Ok(0x9)),
            (0x8, 0x0f, 0x1, Ok(0x9)),
            (0, 0x0f, 0x10, Err(0x10)),
            (0x10, 0x0f, 0, Err(0x10)),
        ];

        for (must_be_one, may_be_one, requested, expected) in cases {
            let capability = ControlCapability {
                must_be_one,
                may_be_one,
            };
            match (
                capability.adjust(ControlField::VmEntry, requested),
                expected,
            ) {
                (Ok(actual), Ok(wanted)) => assert_eq!(actual, wanted),
                (Err(error), Err(missing)) => {
                    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
                    assert_eq!(error.detail & u64::from(u32::MAX), missing as u64);
                }
                (actual, wanted) => panic!("unexpected result: {actual:?}, wanted {wanted:?}"),
            }
        }
    }

    #[test]
    fn native_instruction_controls_are_requested_explicitly() {
        let capabilities = ControlCapabilities {
            pinbased: ControlCapability::unrestricted(),
            primary: ControlCapability::unrestricted(),
            secondary: ControlCapability::unrestricted(),
            vmexit: ControlCapability::unrestricted(),
            vmentry: ControlCapability::unrestricted(),
        };
        let native = ENABLE_RDTSCP | ENABLE_INVPCID | ENABLE_USER_WAIT_PAUSE;
        let controls = capabilities
            .controls_for(native)
            .expect("supported controls");
        assert_eq!(
            controls.secondary,
            REQUIRED_SECONDARY | ENABLE_RDTSCP | ENABLE_INVPCID | ENABLE_USER_WAIT_PAUSE
        );
    }
}
