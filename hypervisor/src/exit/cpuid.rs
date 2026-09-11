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

pub fn handle(vcpu: &mut Vcpu, guest_cr4: u64) -> ExitDisposition {
    let leaf = vcpu.regs.rax as u32;
    let subleaf = vcpu.regs.rcx as u32;

    let mut cpuid_result = if leaf == 0xd && subleaf <= 1 {
        // safety: the VMX state boundary maintains validated root/guest masks.
        unsafe {
            crate::arch::intel::caps::guest_xsave_cpuid(subleaf, vcpu.guest_xcr0, vcpu.root_xcr0)
        }
    } else {
        cpuid(leaf, subleaf)
    };
    if leaf == 7 && subleaf == 0 {
        cpuid_result.ecx.set_bit(4, guest_cr4 & (1 << 22) != 0);
    }

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
