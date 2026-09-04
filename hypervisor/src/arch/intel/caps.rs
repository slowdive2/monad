use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};

use wdk_sys::{
    ntddk::{
        KeGetCurrentIrql, KeGetCurrentProcessorNumberEx, KeRevertToUserGroupAffinityThread,
        KeSetSystemGroupAffinityThread,
    },
    GROUP_AFFINITY, KAFFINITY, PROCESSOR_NUMBER,
};

use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};
use crate::topology::{snapshot_active_processors, CpuId, CpuTopology};

use super::control::{
    ControlCapabilities, ControlCapability, VmxControls, ENABLE_INVPCID, ENABLE_RDTSCP,
    ENABLE_USER_WAIT_PAUSE, ENABLE_XSAVES_XRSTORS,
};
use super::state::read_msr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidRegisters {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidRegisters {
    let result = __cpuid_count(leaf, subleaf);
    CpuidRegisters {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

pub fn current_initial_apic_id() -> u32 {
    cpuid(1, 0).ebx >> 24
}

pub const MAX_XSAVE_BYTES: usize = 64 * 1024;
const PASSIVE_LEVEL: u8 = 0;

const IA32_FEATURE_CONTROL: u32 = 0x3a;
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
const IA32_VMX_CR4_FIXED1: u32 = 0x489;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48b;
const IA32_VMX_EPT_VPID_CAP: u32 = 0x48c;
const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48d;
const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48e;
const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48f;
const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;

const FEATURE_CONTROL_LOCK: u64 = 1 << 0;
const FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;
const VMX_BASIC_TRUE_CONTROLS: u64 = 1 << 55;
const VMX_BASIC_MEMORY_TYPE_SHIFT: u32 = 50;
const VMX_BASIC_MEMORY_TYPE_MASK: u64 = 0xf;
const MEMORY_TYPE_WRITE_BACK: u8 = 6;

const EPT_EXECUTE_ONLY: u64 = 1 << 0;
const EPT_WALK_LENGTH_4: u64 = 1 << 6;
const EPT_MEMORY_TYPE_WB: u64 = 1 << 14;
const EPT_PAGE_2M: u64 = 1 << 16;
const EPT_PAGE_1G: u64 = 1 << 17;
const EPT_INVEPT: u64 = 1 << 20;
const EPT_ACCESSED_DIRTY: u64 = 1 << 21;
const EPT_INVEPT_SINGLE: u64 = 1 << 25;
const EPT_INVEPT_ALL: u64 = 1 << 26;

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredCapability {
    Vmx = 0,
    FeatureControlLocked = 1,
    VmxOutsideSmx = 2,
    VmxRegionWriteBack = 3,
    VmxRevision = 4,
    Cr0FixedMasks = 5,
    Cr4FixedMasks = 6,
    Ept = 7,
    EptFourLevel = 8,
    EptWriteBack = 9,
    EptPage2M = 10,
    Invept = 11,
    InveptSingle = 12,
    InveptAll = 13,
    EptPage1G = 14,
    Xsave = 15,
    Xsaves = 16,
    XsaveLayout = 17,
    PhysicalAddressWidth = 18,
    ProcessorCount = 19,
    ConsistentAcrossProcessors = 20,
    RdtscpControl = 21,
    InvpcidControl = 22,
    XsavesControl = 23,
    WaitpkgControl = 24,
}

impl RequiredCapability {
    const ORDERED: [Self; 24] = [
        Self::Vmx,
        Self::FeatureControlLocked,
        Self::VmxOutsideSmx,
        Self::VmxRegionWriteBack,
        Self::VmxRevision,
        Self::Cr0FixedMasks,
        Self::Cr4FixedMasks,
        Self::Ept,
        Self::EptFourLevel,
        Self::EptWriteBack,
        Self::EptPage2M,
        Self::Invept,
        Self::InveptSingle,
        Self::InveptAll,
        Self::EptPage1G,
        Self::Xsave,
        Self::Xsaves,
        Self::XsaveLayout,
        Self::PhysicalAddressWidth,
        Self::ProcessorCount,
        Self::RdtscpControl,
        Self::InvpcidControl,
        Self::XsavesControl,
        Self::WaitpkgControl,
    ];
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestFeatureContract {
    pub rdtscp: bool,
    pub invpcid: bool,
    pub xsaves: bool,
    pub waitpkg: bool,
}

impl GuestFeatureContract {
    pub const fn requested_secondary_controls(self) -> u32 {
        (if self.rdtscp { ENABLE_RDTSCP } else { 0 })
            | (if self.invpcid { ENABLE_INVPCID } else { 0 })
            | (if self.xsaves {
                ENABLE_XSAVES_XRSTORS
            } else {
                0
            })
            | (if self.waitpkg {
                ENABLE_USER_WAIT_PAUSE
            } else {
                0
            })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XsaveComponent {
    pub size: u32,
    pub standard_offset: u32,
    pub supervisor: bool,
    pub align64: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XsaveLayout {
    pub xcr0_mask: u64,
    pub xss_mask: u64,
    pub state_mask: u64,
    pub xcomp_bv: u64,
    pub maximum_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptCapabilities {
    pub four_level_walk: bool,
    pub write_back_walk: bool,
    pub page_2m: bool,
    pub page_1g: bool,
    pub invept: bool,
    pub invept_single: bool,
    pub invept_all: bool,
    pub execute_only: bool,
    pub accessed_dirty: bool,
}

#[derive(Clone)]
pub struct RawCapabilities {
    pub cpuid_1_ecx: u32,
    pub cpuid_7_0_ebx: u32,
    pub cpuid_7_0_ecx: u32,
    pub cpuid_80000001_edx: u32,
    pub cpuid_80000008_eax: u32,
    pub cpuid_d1_eax: u32,
    pub xcr0_supported: u64,
    pub xss_supported: u64,
    pub feature_control: u64,
    pub vmx_basic: u64,
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
    pub pinbased_controls: u64,
    pub primary_controls: u64,
    pub secondary_controls: u64,
    pub exit_controls: u64,
    pub entry_controls: u64,
    pub ept_vpid: u64,
    pub processor_count: u16,
    pub xsave_components: [XsaveComponent; 64],
}

impl Default for RawCapabilities {
    fn default() -> Self {
        Self {
            cpuid_1_ecx: 0,
            cpuid_7_0_ebx: 0,
            cpuid_7_0_ecx: 0,
            cpuid_80000001_edx: 0,
            cpuid_80000008_eax: 0,
            cpuid_d1_eax: 0,
            xcr0_supported: 0,
            xss_supported: 0,
            feature_control: 0,
            vmx_basic: 0,
            cr0_fixed0: 0,
            cr0_fixed1: 0,
            cr4_fixed0: 0,
            cr4_fixed1: 0,
            pinbased_controls: 0,
            primary_controls: 0,
            secondary_controls: 0,
            exit_controls: 0,
            entry_controls: 0,
            ept_vpid: 0,
            processor_count: 0,
            xsave_components: [XsaveComponent::default(); 64],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntelCapabilities {
    pub vmx_revision_id: u32,
    pub max_physical_address_bits: u8,
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
    pub ept: EptCapabilities,
    pub control_capabilities: ControlCapabilities,
    pub controls: VmxControls,
    pub guest_features: GuestFeatureContract,
    pub xsave: XsaveLayout,
}

pub struct ValidatedPlatform {
    pub capabilities: IntelCapabilities,
    pub topology: CpuTopology,
    permit: VmxonPermit,
}

#[derive(Clone, Copy)]
pub struct VmxonPermit {
    _private: (),
}

impl ValidatedPlatform {
    pub(crate) const fn vmxon_permit(&self) -> VmxonPermit {
        self.permit
    }
}

fn unsupported(detail: RequiredCapability) -> MonadError {
    MonadError::new(
        ErrorPhase::Capability,
        ErrorCode::UnsupportedCapability,
        detail as u64,
    )
}

fn component_mask(raw: &RawCapabilities) -> u64 {
    raw.xcr0_supported | raw.xss_supported
}

fn guest_feature_contract(raw: &RawCapabilities) -> GuestFeatureContract {
    GuestFeatureContract {
        rdtscp: raw.cpuid_80000001_edx & (1 << 27) != 0,
        invpcid: raw.cpuid_7_0_ebx & (1 << 10) != 0,
        xsaves: raw.cpuid_d1_eax & (1 << 3) != 0,
        waitpkg: raw.cpuid_7_0_ecx & (1 << 5) != 0,
    }
}

fn secondary_control_available(raw: &RawCapabilities, control: u32) -> bool {
    ControlCapability::from_msr(raw.secondary_controls)
        .adjust(
            super::control::ControlField::SecondaryProcessorBased,
            control,
        )
        .is_ok()
}

fn align_up(value: u32, alignment: u32) -> Option<u32> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum & !(alignment - 1))
}

pub fn calculate_xsave_layout(raw: &RawCapabilities) -> MonadResult<XsaveLayout> {
    if raw.xcr0_supported & raw.xss_supported != 0 || raw.xss_supported & 0x3 != 0 {
        return Err(unsupported(RequiredCapability::XsaveLayout));
    }
    let mask = component_mask(raw);
    if mask & (1u64 << 63) != 0 {
        return Err(unsupported(RequiredCapability::XsaveLayout));
    }
    let mut compacted_end = 576u32;

    for index in 2..64usize {
        if mask & (1u64 << index) == 0 {
            continue;
        }
        let component = raw.xsave_components[index];
        if component.size == 0 || component.supervisor != (raw.xss_supported & (1u64 << index) != 0)
        {
            return Err(unsupported(RequiredCapability::XsaveLayout));
        }
        if !component.supervisor {
            let standard_end = component
                .standard_offset
                .checked_add(component.size)
                .ok_or_else(|| unsupported(RequiredCapability::XsaveLayout))?;
            if component.standard_offset < 576 || standard_end as usize > MAX_XSAVE_BYTES {
                return Err(unsupported(RequiredCapability::XsaveLayout));
            }
            for prior_index in 2..index {
                if mask & (1u64 << prior_index) == 0 {
                    continue;
                }
                let prior = raw.xsave_components[prior_index];
                if prior.supervisor {
                    continue;
                }
                let Some(prior_end) = prior.standard_offset.checked_add(prior.size) else {
                    return Err(unsupported(RequiredCapability::XsaveLayout));
                };
                if component.standard_offset < prior_end && prior.standard_offset < standard_end {
                    return Err(unsupported(RequiredCapability::XsaveLayout));
                }
            }
        }

        if component.align64 {
            compacted_end = align_up(compacted_end, 64)
                .ok_or_else(|| unsupported(RequiredCapability::XsaveLayout))?;
        }
        compacted_end = compacted_end
            .checked_add(component.size)
            .ok_or_else(|| unsupported(RequiredCapability::XsaveLayout))?;
        if compacted_end as usize > MAX_XSAVE_BYTES {
            return Err(unsupported(RequiredCapability::XsaveLayout));
        }
    }

    Ok(XsaveLayout {
        xcr0_mask: raw.xcr0_supported,
        xss_mask: raw.xss_supported,
        state_mask: mask,
        xcomp_bv: mask | (1u64 << 63),
        maximum_size: compacted_end,
    })
}

fn has(raw: &RawCapabilities, capability: RequiredCapability) -> bool {
    match capability {
        RequiredCapability::Vmx => raw.cpuid_1_ecx & (1 << 5) != 0,
        RequiredCapability::FeatureControlLocked => raw.feature_control & FEATURE_CONTROL_LOCK != 0,
        RequiredCapability::VmxOutsideSmx => {
            raw.feature_control & FEATURE_CONTROL_VMX_OUTSIDE_SMX != 0
        }
        RequiredCapability::VmxRegionWriteBack => {
            ((raw.vmx_basic >> VMX_BASIC_MEMORY_TYPE_SHIFT) & VMX_BASIC_MEMORY_TYPE_MASK) as u8
                == MEMORY_TYPE_WRITE_BACK
        }
        RequiredCapability::VmxRevision => raw.vmx_basic as u32 & 0x7fff_ffff != 0,
        RequiredCapability::Cr0FixedMasks => raw.cr0_fixed0 & !raw.cr0_fixed1 == 0,
        RequiredCapability::Cr4FixedMasks => raw.cr4_fixed0 & !raw.cr4_fixed1 == 0,
        RequiredCapability::Ept => ControlCapability::from_msr(raw.secondary_controls)
            .adjust(
                super::control::ControlField::SecondaryProcessorBased,
                1 << 1,
            )
            .is_ok(),
        RequiredCapability::EptFourLevel => raw.ept_vpid & EPT_WALK_LENGTH_4 != 0,
        RequiredCapability::EptWriteBack => raw.ept_vpid & EPT_MEMORY_TYPE_WB != 0,
        RequiredCapability::EptPage2M => raw.ept_vpid & EPT_PAGE_2M != 0,
        RequiredCapability::Invept => raw.ept_vpid & EPT_INVEPT != 0,
        RequiredCapability::InveptSingle => raw.ept_vpid & EPT_INVEPT_SINGLE != 0,
        RequiredCapability::InveptAll => raw.ept_vpid & EPT_INVEPT_ALL != 0,
        RequiredCapability::EptPage1G => raw.ept_vpid & EPT_PAGE_1G != 0,
        RequiredCapability::Xsave => {
            raw.cpuid_1_ecx & (1 << 26) != 0 && raw.xcr0_supported & 0x3 == 0x3
        }
        RequiredCapability::Xsaves => raw.cpuid_d1_eax & (1 << 3) != 0,
        RequiredCapability::XsaveLayout => calculate_xsave_layout(raw).is_ok(),
        RequiredCapability::PhysicalAddressWidth => {
            let width = raw.cpuid_80000008_eax as u8;
            (1..=48).contains(&width)
        }
        RequiredCapability::ProcessorCount => (1..=256).contains(&raw.processor_count),
        RequiredCapability::ConsistentAcrossProcessors => true,
        RequiredCapability::RdtscpControl => {
            !guest_feature_contract(raw).rdtscp || secondary_control_available(raw, ENABLE_RDTSCP)
        }
        RequiredCapability::InvpcidControl => {
            !guest_feature_contract(raw).invpcid || secondary_control_available(raw, ENABLE_INVPCID)
        }
        RequiredCapability::XsavesControl => {
            !guest_feature_contract(raw).xsaves
                || secondary_control_available(raw, ENABLE_XSAVES_XRSTORS)
        }
        RequiredCapability::WaitpkgControl => {
            !guest_feature_contract(raw).waitpkg
                || secondary_control_available(raw, ENABLE_USER_WAIT_PAUSE)
        }
    }
}

pub fn validate_required_capabilities(raw: &RawCapabilities) -> MonadResult<IntelCapabilities> {
    if raw.cpuid_1_ecx & (1 << 31) != 0 {
        return Err(MonadError::new(
            ErrorPhase::Capability,
            ErrorCode::CompetingHypervisor,
            1,
        ));
    }
    for capability in RequiredCapability::ORDERED {
        if !has(raw, capability) {
            if capability == RequiredCapability::PhysicalAddressWidth
                && raw.cpuid_80000008_eax as u8 > 48
            {
                return Err(MonadError::new(
                    ErrorPhase::Capability,
                    ErrorCode::PhysicalAddressTooWide,
                    u64::from(raw.cpuid_80000008_eax as u8),
                ));
            }
            if capability == RequiredCapability::ProcessorCount && raw.processor_count > 256 {
                return Err(MonadError::new(
                    ErrorPhase::Capability,
                    ErrorCode::TooManyProcessors,
                    u64::from(raw.processor_count),
                ));
            }
            return Err(unsupported(capability));
        }
    }

    let control_capabilities = ControlCapabilities {
        pinbased: ControlCapability::from_msr(raw.pinbased_controls),
        primary: ControlCapability::from_msr(raw.primary_controls),
        secondary: ControlCapability::from_msr(raw.secondary_controls),
        vmexit: ControlCapability::from_msr(raw.exit_controls),
        vmentry: ControlCapability::from_msr(raw.entry_controls),
    };
    let guest_features = guest_feature_contract(raw);
    let controls =
        control_capabilities.controls_for(guest_features.requested_secondary_controls())?;
    Ok(IntelCapabilities {
        vmx_revision_id: raw.vmx_basic as u32 & 0x7fff_ffff,
        max_physical_address_bits: raw.cpuid_80000008_eax as u8,
        cr0_fixed0: raw.cr0_fixed0,
        cr0_fixed1: raw.cr0_fixed1,
        cr4_fixed0: raw.cr4_fixed0,
        cr4_fixed1: raw.cr4_fixed1,
        ept: EptCapabilities {
            four_level_walk: raw.ept_vpid & EPT_WALK_LENGTH_4 != 0,
            write_back_walk: raw.ept_vpid & EPT_MEMORY_TYPE_WB != 0,
            page_2m: raw.ept_vpid & EPT_PAGE_2M != 0,
            page_1g: raw.ept_vpid & EPT_PAGE_1G != 0,
            invept: raw.ept_vpid & EPT_INVEPT != 0,
            invept_single: raw.ept_vpid & EPT_INVEPT_SINGLE != 0,
            invept_all: raw.ept_vpid & EPT_INVEPT_ALL != 0,
            execute_only: raw.ept_vpid & EPT_EXECUTE_ONLY != 0,
            accessed_dirty: raw.ept_vpid & EPT_ACCESSED_DIRTY != 0,
        },
        control_capabilities,
        controls,
        guest_features,
        xsave: calculate_xsave_layout(raw)?,
    })
}

fn cpuid_mask(result: CpuidResult) -> u64 {
    u64::from(result.eax) | (u64::from(result.edx) << 32)
}

struct AffinityGuard {
    previous: GROUP_AFFINITY,
}

impl Drop for AffinityGuard {
    fn drop(&mut self) {
        // safety: `previous` came from the affinity call on this thread.
        unsafe { KeRevertToUserGroupAffinityThread(&mut self.previous) };
    }
}

fn pin_to_processor(cpu: CpuId) -> MonadResult<AffinityGuard> {
    // safety: these pod values allow zero initialization.
    let mut target = unsafe { core::mem::zeroed::<GROUP_AFFINITY>() };
    // safety: the affinity call fills this zeroable pod before guard creation.
    let mut previous = unsafe { core::mem::zeroed::<GROUP_AFFINITY>() };
    target.Group = cpu.group;
    target.Mask = (1 as KAFFINITY) << cpu.number;
    // safety: the active topology supplied the target; this runs at passive_level.
    unsafe { KeSetSystemGroupAffinityThread(&mut target, &mut previous) };
    let guard = AffinityGuard { previous };

    let mut current = PROCESSOR_NUMBER::default();
    // safety: `current` is writable output storage.
    unsafe { KeGetCurrentProcessorNumberEx(&mut current) };
    if current.Group != cpu.group || current.Number != cpu.number {
        return Err(MonadError::new(
            ErrorPhase::Topology,
            ErrorCode::TopologyChanged,
            u64::from(cpu.dense_index),
        )
        .on_cpu(cpu.dense_index));
    }
    Ok(guard)
}

fn collect_processor_capabilities(
    processor_count: u16,
    cpu: CpuId,
) -> MonadResult<RawCapabilities> {
    let leaf1 = __cpuid(1);
    if leaf1.ecx & (1 << 31) != 0 {
        return Err(
            MonadError::new(ErrorPhase::Capability, ErrorCode::CompetingHypervisor, 1)
                .on_cpu(cpu.dense_index),
        );
    }
    if leaf1.ecx & (1 << 5) == 0 {
        return Err(unsupported(RequiredCapability::Vmx).on_cpu(cpu.dense_index));
    }

    let extended = __cpuid(0x8000_0008);
    let extended_features = __cpuid(0x8000_0001);
    let leaf7 = __cpuid_count(7, 0);
    let leaf_d0 = __cpuid_count(0x0d, 0);
    let leaf_d1 = __cpuid_count(0x0d, 1);
    let vmx_basic = read_msr(IA32_VMX_BASIC);
    let true_controls = vmx_basic & VMX_BASIC_TRUE_CONTROLS != 0;
    let mut raw = RawCapabilities {
        cpuid_1_ecx: leaf1.ecx,
        cpuid_7_0_ebx: leaf7.ebx,
        cpuid_7_0_ecx: leaf7.ecx,
        cpuid_80000001_edx: extended_features.edx,
        cpuid_80000008_eax: extended.eax,
        cpuid_d1_eax: leaf_d1.eax,
        xcr0_supported: cpuid_mask(leaf_d0),
        xss_supported: u64::from(leaf_d1.ecx) | (u64::from(leaf_d1.edx) << 32),
        feature_control: read_msr(IA32_FEATURE_CONTROL),
        vmx_basic,
        cr0_fixed0: read_msr(IA32_VMX_CR0_FIXED0),
        cr0_fixed1: read_msr(IA32_VMX_CR0_FIXED1),
        cr4_fixed0: read_msr(IA32_VMX_CR4_FIXED0),
        cr4_fixed1: read_msr(IA32_VMX_CR4_FIXED1),
        pinbased_controls: read_msr(if true_controls {
            IA32_VMX_TRUE_PINBASED_CTLS
        } else {
            IA32_VMX_PINBASED_CTLS
        }),
        primary_controls: read_msr(if true_controls {
            IA32_VMX_TRUE_PROCBASED_CTLS
        } else {
            IA32_VMX_PROCBASED_CTLS
        }),
        secondary_controls: read_msr(IA32_VMX_PROCBASED_CTLS2),
        exit_controls: read_msr(if true_controls {
            IA32_VMX_TRUE_EXIT_CTLS
        } else {
            IA32_VMX_EXIT_CTLS
        }),
        entry_controls: read_msr(if true_controls {
            IA32_VMX_TRUE_ENTRY_CTLS
        } else {
            IA32_VMX_ENTRY_CTLS
        }),
        ept_vpid: read_msr(IA32_VMX_EPT_VPID_CAP),
        processor_count,
        ..RawCapabilities::default()
    };
    let supported = component_mask(&raw);
    for index in 2..64usize {
        if supported & (1u64 << index) == 0 {
            continue;
        }
        let component = __cpuid_count(0x0d, index as u32);
        raw.xsave_components[index] = XsaveComponent {
            size: component.eax,
            standard_offset: component.ebx,
            supervisor: component.ecx & 1 != 0,
            align64: component.ecx & 2 != 0,
        };
    }
    Ok(raw)
}

fn accumulate_processor_capabilities(
    platform: &mut Option<IntelCapabilities>,
    capabilities: IntelCapabilities,
    cpu_dense_index: u16,
) -> MonadResult<()> {
    if let Some(expected) = platform {
        if capabilities != *expected {
            return Err(
                unsupported(RequiredCapability::ConsistentAcrossProcessors).on_cpu(cpu_dense_index)
            );
        }
    } else {
        *platform = Some(capabilities);
    }
    Ok(())
}

/// reads and checks the platform state needed before vmx.
///
/// call once at `PASSIVE_LEVEL` during vmm preparation. it pins the caller to
/// each processor and reads every capability register exactly once for that
/// processor before returning one homogeneous platform snapshot.
pub fn collect_capabilities() -> MonadResult<ValidatedPlatform> {
    // safety: this pointer-free read only rejects an
    // invalid caller context before any other platform operation.
    if unsafe { KeGetCurrentIrql() } != PASSIVE_LEVEL {
        return Err(MonadError::new(
            ErrorPhase::Capability,
            ErrorCode::InvalidLifecycleState,
            0,
        ));
    }

    let topology = snapshot_active_processors()?;
    let mut platform_capabilities = None;
    for cpu in topology.ids().iter().copied() {
        let _affinity = pin_to_processor(cpu)?;
        let raw = collect_processor_capabilities(topology.len(), cpu)?;
        let capabilities =
            validate_required_capabilities(&raw).map_err(|error| error.on_cpu(cpu.dense_index))?;
        accumulate_processor_capabilities(
            &mut platform_capabilities,
            capabilities,
            cpu.dense_index,
        )?;
    }

    let capabilities = platform_capabilities
        .ok_or_else(|| MonadError::new(ErrorPhase::Topology, ErrorCode::InvalidCpuSet, 0))?;
    Ok(ValidatedPlatform {
        capabilities,
        topology,
        permit: VmxonPermit { _private: () },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::intel::control::{
        ENABLE_EPT, REQUIRED_PRIMARY, REQUIRED_SECONDARY, REQUIRED_VMENTRY, REQUIRED_VMEXIT,
    };

    fn capability_msr(required: u32) -> u64 {
        u64::from(required) | (u64::from(u32::MAX) << 32)
    }

    fn valid_raw() -> RawCapabilities {
        RawCapabilities {
            cpuid_1_ecx: (1 << 5) | (1 << 26),
            cpuid_7_0_ebx: 1 << 10,
            cpuid_7_0_ecx: 1 << 5,
            cpuid_80000001_edx: 1 << 27,
            cpuid_80000008_eax: 48,
            cpuid_d1_eax: 1 << 3,
            xcr0_supported: 0x3,
            feature_control: FEATURE_CONTROL_LOCK | FEATURE_CONTROL_VMX_OUTSIDE_SMX,
            vmx_basic: 1 | ((MEMORY_TYPE_WRITE_BACK as u64) << VMX_BASIC_MEMORY_TYPE_SHIFT),
            cr0_fixed0: 0x20,
            cr0_fixed1: u64::MAX,
            cr4_fixed0: 0,
            cr4_fixed1: u64::MAX,
            pinbased_controls: capability_msr(0),
            primary_controls: capability_msr(REQUIRED_PRIMARY),
            secondary_controls: capability_msr(REQUIRED_SECONDARY),
            exit_controls: capability_msr(REQUIRED_VMEXIT),
            entry_controls: capability_msr(REQUIRED_VMENTRY),
            ept_vpid: EPT_WALK_LENGTH_4
                | EPT_MEMORY_TYPE_WB
                | EPT_PAGE_2M
                | EPT_PAGE_1G
                | EPT_INVEPT
                | EPT_INVEPT_SINGLE
                | EPT_INVEPT_ALL,
            processor_count: 1,
            ..RawCapabilities::default()
        }
    }

    #[test]
    fn capability_each_required_bit_missing() {
        for missing in RequiredCapability::ORDERED {
            let mut raw = valid_raw();
            match missing {
                RequiredCapability::Vmx => raw.cpuid_1_ecx &= !(1 << 5),
                RequiredCapability::FeatureControlLocked => {
                    raw.feature_control &= !FEATURE_CONTROL_LOCK
                }
                RequiredCapability::VmxOutsideSmx => {
                    raw.feature_control &= !FEATURE_CONTROL_VMX_OUTSIDE_SMX
                }
                RequiredCapability::VmxRegionWriteBack => raw.vmx_basic &= !(0xf << 50),
                RequiredCapability::VmxRevision => raw.vmx_basic &= !0x7fff_ffff,
                RequiredCapability::Cr0FixedMasks => {
                    raw.cr0_fixed0 = 1 << 63;
                    raw.cr0_fixed1 &= !(1 << 63);
                }
                RequiredCapability::Cr4FixedMasks => {
                    raw.cr4_fixed0 = 1 << 63;
                    raw.cr4_fixed1 &= !(1 << 63);
                }
                RequiredCapability::Ept => raw.secondary_controls &= !(u64::from(ENABLE_EPT) << 32),
                RequiredCapability::EptFourLevel => raw.ept_vpid &= !EPT_WALK_LENGTH_4,
                RequiredCapability::EptWriteBack => raw.ept_vpid &= !EPT_MEMORY_TYPE_WB,
                RequiredCapability::EptPage2M => raw.ept_vpid &= !EPT_PAGE_2M,
                RequiredCapability::Invept => raw.ept_vpid &= !EPT_INVEPT,
                RequiredCapability::InveptSingle => raw.ept_vpid &= !EPT_INVEPT_SINGLE,
                RequiredCapability::InveptAll => raw.ept_vpid &= !EPT_INVEPT_ALL,
                RequiredCapability::EptPage1G => raw.ept_vpid &= !EPT_PAGE_1G,
                RequiredCapability::Xsave => raw.cpuid_1_ecx &= !(1 << 26),
                RequiredCapability::Xsaves => raw.cpuid_d1_eax &= !(1 << 3),
                RequiredCapability::XsaveLayout => {
                    raw.xcr0_supported |= 1 << 2;
                    raw.xsave_components[2].size = 0;
                }
                RequiredCapability::PhysicalAddressWidth => raw.cpuid_80000008_eax = 49,
                RequiredCapability::ProcessorCount => raw.processor_count = 0,
                RequiredCapability::RdtscpControl => {
                    raw.secondary_controls &=
                        !(u64::from(ENABLE_RDTSCP) | (u64::from(ENABLE_RDTSCP) << 32))
                }
                RequiredCapability::InvpcidControl => {
                    raw.secondary_controls &=
                        !(u64::from(ENABLE_INVPCID) | (u64::from(ENABLE_INVPCID) << 32))
                }
                RequiredCapability::XsavesControl => {
                    raw.secondary_controls &= !(u64::from(ENABLE_XSAVES_XRSTORS)
                        | (u64::from(ENABLE_XSAVES_XRSTORS) << 32))
                }
                RequiredCapability::WaitpkgControl => {
                    raw.secondary_controls &= !(u64::from(ENABLE_USER_WAIT_PAUSE)
                        | (u64::from(ENABLE_USER_WAIT_PAUSE) << 32))
                }
                RequiredCapability::ConsistentAcrossProcessors => {
                    panic!("cross-processor consistency is tested during collection")
                }
            }
            let error = validate_required_capabilities(&raw)
                .expect_err("missing required capability must fail");
            if missing == RequiredCapability::PhysicalAddressWidth {
                assert_eq!(error.code, ErrorCode::PhysicalAddressTooWide);
                assert_eq!(error.detail, 49);
            } else {
                assert_eq!(error.code, ErrorCode::UnsupportedCapability);
                assert_eq!(error.detail, missing as u64);
            }
        }

        let mut too_many = valid_raw();
        too_many.processor_count = 257;
        let error =
            validate_required_capabilities(&too_many).expect_err("257 processors must be rejected");
        assert_eq!(error.code, ErrorCode::TooManyProcessors);
        assert_eq!(error.detail, 257);

        let mut optional = valid_raw();
        optional.ept_vpid |= EPT_EXECUTE_ONLY | EPT_ACCESSED_DIRTY;
        let capabilities =
            validate_required_capabilities(&optional).expect("optional EPT features parse");
        assert!(capabilities.ept.execute_only);
        assert!(capabilities.ept.accessed_dirty);

        let first = validate_required_capabilities(&valid_raw()).expect("first processor");
        let mut second_raw = valid_raw();
        second_raw.ept_vpid |= EPT_EXECUTE_ONLY;
        let second = validate_required_capabilities(&second_raw).expect("second processor");
        let mut platform = Some(first);
        let mismatch = accumulate_processor_capabilities(&mut platform, second, 1)
            .expect_err("heterogeneous capability snapshots must fail");
        assert_eq!(
            mismatch.detail,
            RequiredCapability::ConsistentAcrossProcessors as u64
        );
        assert_eq!(mismatch.cpu_dense_index, 1);
    }

    #[test]
    fn capability_competing_hypervisor() {
        let mut raw = valid_raw();
        raw.cpuid_1_ecx |= 1 << 31;
        let error = validate_required_capabilities(&raw).expect_err("hypervisor-present must fail");
        assert_eq!(error.code, ErrorCode::CompetingHypervisor);
    }

    #[test]
    fn guest_cpuid_features_have_matching_execution_controls() {
        let capabilities = validate_required_capabilities(&valid_raw()).expect("valid platform");
        assert_eq!(
            capabilities.controls.secondary
                & (ENABLE_RDTSCP | ENABLE_INVPCID | ENABLE_XSAVES_XRSTORS | ENABLE_USER_WAIT_PAUSE),
            ENABLE_RDTSCP | ENABLE_INVPCID | ENABLE_XSAVES_XRSTORS | ENABLE_USER_WAIT_PAUSE
        );
        assert!(capabilities.guest_features.rdtscp);
        assert!(capabilities.guest_features.invpcid);
        assert!(capabilities.guest_features.xsaves);
        assert!(capabilities.guest_features.waitpkg);

        let mut without_optional_features = valid_raw();
        without_optional_features.cpuid_7_0_ebx = 0;
        without_optional_features.cpuid_7_0_ecx = 0;
        without_optional_features.cpuid_80000001_edx = 0;
        let capabilities = validate_required_capabilities(&without_optional_features)
            .expect("optional native features may be absent");
        assert_eq!(
            capabilities.controls.secondary
                & (ENABLE_RDTSCP | ENABLE_INVPCID | ENABLE_USER_WAIT_PAUSE),
            0
        );
        assert_eq!(
            capabilities.controls.secondary & ENABLE_XSAVES_XRSTORS,
            ENABLE_XSAVES_XRSTORS
        );
    }

    #[test]
    fn xsave_layout() {
        let mut raw = valid_raw();
        raw.xcr0_supported |= (1 << 2) | (1 << 3);
        raw.xsave_components[2] = XsaveComponent {
            size: 256,
            standard_offset: 576,
            supervisor: false,
            align64: false,
        };
        raw.xsave_components[3] = XsaveComponent {
            size: 64,
            standard_offset: 832,
            supervisor: false,
            align64: true,
        };
        let layout = calculate_xsave_layout(&raw).expect("valid xsave layout");
        assert_eq!(layout.maximum_size, 896);
        assert_eq!(layout.maximum_size % 64, 0);

        raw.xsave_components[3].standard_offset = 800;
        assert!(calculate_xsave_layout(&raw).is_err());
        raw.xsave_components[3].standard_offset = 832;

        raw.xcr0_supported &= !(1 << 3);
        raw.xss_supported |= 1 << 3;
        raw.xsave_components[3].standard_offset = 0;
        raw.xsave_components[3].supervisor = true;
        let supervisor = calculate_xsave_layout(&raw).expect("supervisor compacted component");
        assert_eq!(supervisor.state_mask & (1 << 3), 1 << 3);
        assert_eq!(supervisor.xcomp_bv & (1 << 63), 1 << 63);

        raw.xss_supported &= !(1 << 3);
        raw.xcr0_supported |= 1 << 3;
        raw.xsave_components[3].standard_offset = 832;
        raw.xsave_components[3].supervisor = false;
        raw.xsave_components[3].size = MAX_XSAVE_BYTES as u32;
        assert!(calculate_xsave_layout(&raw).is_err());
        raw.xsave_components[3].size = MAX_XSAVE_BYTES as u32 - 832;
        let exact = calculate_xsave_layout(&raw).expect("exact maximum is permitted");
        assert_eq!(exact.maximum_size, MAX_XSAVE_BYTES as u32);

        let mut overlapping_ownership = valid_raw();
        overlapping_ownership.xcr0_supported |= 1 << 2;
        overlapping_ownership.xss_supported |= 1 << 2;
        overlapping_ownership.xsave_components[2] = XsaveComponent {
            size: 64,
            standard_offset: 576,
            supervisor: true,
            align64: false,
        };
        assert!(calculate_xsave_layout(&overlapping_ownership).is_err());
    }
}
