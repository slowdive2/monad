use bit_field::BitField;

use crate::arch::intel::caps::cpuid;
use crate::vmm::Vcpu;

use super::disposition::ExitDisposition;

enum CpuidLeaf {
    FeatureInformation = 0x1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum FeatureBits {
    HypervisorPresentBit = 31,
}

pub fn handle(vcpu: &mut Vcpu) -> ExitDisposition {
    let leaf = vcpu.regs.rax as u32;
    let subleaf = vcpu.regs.rcx as u32;

    let mut cpuid_result = cpuid(leaf, subleaf);

    if leaf == CpuidLeaf::FeatureInformation as u32 {
        cpuid_result
            .ecx
            .set_bit(FeatureBits::HypervisorPresentBit as usize, false);
    }

    vcpu.regs.rax = cpuid_result.eax as u64;
    vcpu.regs.rbx = cpuid_result.ebx as u64;
    vcpu.regs.rcx = cpuid_result.ecx as u64;
    vcpu.regs.rdx = cpuid_result.edx as u64;

    ExitDisposition::ResumeAndAdvance
}
