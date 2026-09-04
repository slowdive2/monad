use crate::vmm::Vcpu;

use super::disposition::ExitDisposition;
use super::eventinjection;

pub fn handle(_vcpu: &mut Vcpu) -> ExitDisposition {
    eventinjection::inject_ud()
}
