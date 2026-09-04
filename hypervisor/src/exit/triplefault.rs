// triple faults are fatal. don't reset the chipset or shut down locally here.

use crate::vmm::Vcpu;

use super::disposition::{ExitDisposition, FatalReason};

const fn disposition() -> ExitDisposition {
    ExitDisposition::Fatal(FatalReason::TripleFault)
}

pub fn handle(_vcpu: &Vcpu) -> ExitDisposition {
    disposition()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_fault_never_uses_reset_port() {
        let result = disposition();
        assert_eq!(result, ExitDisposition::Fatal(FatalReason::TripleFault));
        assert!(!result.advances_rip());
    }
}
