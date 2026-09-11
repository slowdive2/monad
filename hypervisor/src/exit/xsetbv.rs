use super::eventinjection::{inject_gp, inject_ud};
use crate::{
    exit::disposition::{ExitDisposition, FatalReason},
    vmm::Vcpu,
};

// No unknown dependency rules may reach the privileged root XSETBV.
pub(crate) const KNOWN_XCR0: u64 = 0xff | (1 << 9) | (3 << 17) | (1 << 19);

pub(crate) const fn valid_xcr0(value: u64, supported: u64) -> bool {
    value & !supported == 0
        && value & 1 != 0
        && (value & 4 == 0 || value & 2 != 0)
        && matches!(value & (3 << 3), 0 | 0x18)
        && (value & 0xe0 == 0 || (value & 0xe0 == 0xe0 && value & 6 == 6))
        && matches!(value & (3 << 17), 0 | 0x60000)
}

fn admission(
    cs: u16,
    cr4: u64,
    index: u32,
    value: u64,
    supported: u64,
) -> Result<(), ExitDisposition> {
    if cr4 & (1 << 18) == 0 {
        return Err(inject_ud());
    }
    if cs & 3 != 0 || index != 0 || !valid_xcr0(value, supported) {
        return Err(inject_gp());
    }
    if supported & !KNOWN_XCR0 != 0 {
        return Err(ExitDisposition::Fatal(FatalReason::InvalidVcpuState));
    }
    Ok(())
}

pub(super) fn handle(vcpu: &mut Vcpu, cs: u16, cr4: u64) -> ExitDisposition {
    let value = (vcpu.regs.rax as u32 as u64) | ((vcpu.regs.rdx as u32 as u64) << 32);
    if let Err(disposition) = admission(
        cs,
        cr4,
        vcpu.regs.rcx as u32,
        value,
        vcpu.capabilities.xsave.xcr0_mask,
    ) {
        return disposition;
    }
    // Assembly restores all saved components under root_xcr0, then loads this mask.
    vcpu.guest_xcr0 = value;
    ExitDisposition::ResumeAndAdvance
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xsetbv_admission_preserves_exception_priority() {
        let osxsave = 1 << 18;
        assert_eq!(admission(3, 0, 1, 0, KNOWN_XCR0), Err(inject_ud()));
        assert_eq!(admission(3, osxsave, 0, 3, KNOWN_XCR0), Err(inject_gp()));
        assert_eq!(admission(0, osxsave, 1, 3, KNOWN_XCR0), Err(inject_gp()));
        assert_eq!(admission(0, osxsave, 0, 5, KNOWN_XCR0), Err(inject_gp()));
        assert_eq!(admission(0, osxsave, 0, 3, KNOWN_XCR0), Ok(()));
    }

    #[test]
    fn xcr0_dependencies_and_reserved_bits() {
        for value in [1, 3, 7, 0x1f, 0xe7, 0x207, 0x60003, KNOWN_XCR0] {
            assert!(valid_xcr0(value, KNOWN_XCR0), "{value:x}");
        }
        for value in [
            0,
            2,
            5,
            0xb,
            0x13,
            0x27,
            0x67,
            0xe3,
            0x20003,
            0x40003,
            1 << 63,
        ] {
            assert!(!valid_xcr0(value, KNOWN_XCR0), "{value:x}");
        }
        assert!(!valid_xcr0(7, 3));
    }
}
