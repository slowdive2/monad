use crate::vmm::Vcpu;

use super::disposition::{ExitDisposition, FatalReason};
use super::eventinjection;

pub(crate) const fn is_mtrr_write(msr: u32) -> bool {
    matches!(
        msr,
        0x200..=0x20f | 0x250 | 0x258 | 0x259 | 0x268..=0x26f | 0x2ff
    )
}

pub fn handle(vcpu: &mut Vcpu, write: bool) -> ExitDisposition {
    if write && is_mtrr_write(vcpu.regs.rcx as u32) {
        return ExitDisposition::Fatal(FatalReason::MtrrChangedWhileRunning);
    }
    eventinjection::inject_gp()
}
