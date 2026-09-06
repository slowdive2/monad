extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;
use core::sync::atomic::{fence, AtomicBool, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, Ordering};

#[cfg(not(test))]
use wdk_sys::ntddk::KeBugCheckEx;
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePoolWithTag, KeGetCurrentProcessorNumberEx, KeIpiGenericCall,
        MmGetPhysicalAddress,
    },
    POOL_FLAG_NON_PAGED, PROCESSOR_NUMBER,
};

use x86::msr::{IA32_SYSENTER_CS, IA32_SYSENTER_EIP, IA32_SYSENTER_ESP};

use crate::arch::intel::{
    caps::{collect_capabilities, cpuid, IntelCapabilities, ValidatedPlatform, VmxonPermit},
    state::{read_tsc, write_cr3, write_cr4, write_dr7, write_msr, Descriptors, NativeReturnState},
    vmcs::{capture_registers, setup_vmcs, GuestRegs},
    vmx::{
        prepare_control_registers, rendezvous_vmcall, rendezvous_vmcall_bounds,
        restore_control_registers, restore_guest, vmlaunch, vmread, vmresume, vmxoff, vmxon,
        OriginalControlRegisters, VmxRegion, VMX_REGION_SIZE,
    },
};
use crate::ept::{
    build_base_view, collect_raw_mtrr_state, normalize_mtrrs, BackingId, DraftEdit, DraftId,
    EptViewManager, GuestPhysicalAddress, PhysicalInventory, PhysicalRange, ViewId, ViewMetadata,
    WalkResult, WindowsPageAllocator,
};
use crate::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};
use crate::exit::disposition::FatalReason;
use crate::exit::ept_fault::{EptFaultTracker, COMPILED_ALLOWED_VIEW_MASK};
use crate::exit::vmexit::{handle, VmExitAction};
use crate::lifecycle::{
    validate_shutdown_origin, Lifecycle, LifecycleControl, LifecycleState, ShutdownOrigin,
};
use crate::memory::collect_physical_inventory;
use crate::rendezvous::{
    ActiveViewState, CpuResultState, InternalMailbox, MailboxRequest, PublishedViewDirectory,
    RendezvousOperation, RendezvousTransaction,
};
use crate::telemetry::{EventRecord, EventRing, RingSnapshot};
use crate::topology::{snapshot_active_processors, CpuId, CpuSetWord, CpuTopology};
use x86::vmx::vmcs;

const VMM_TAG: u32 = u32::from_le_bytes(*b"Arro");
const PAGE_SIZE: usize = 0x1000;
pub const HOST_STACK_SIZE: usize = 0x6000;
#[cfg(not(test))]
const MONAD_BUGCHECK_CODE: u32 = u32::from_be_bytes(*b"MND1");
const RENDEZVOUS_TSC_BUDGET: u64 = 1 << 34;
const DEFAULT_APERTURE_END: u64 = 1 << 39;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmStartConfig {
    pub session_nonce: u64,
    pub aperture_limit: u64,
    pub rendezvous_timeout_tsc: u64,
    pub device_ranges: Vec<PhysicalRange>,
}

impl VmmStartConfig {
    pub const fn new(session_nonce: u64) -> Self {
        Self {
            session_nonce,
            aperture_limit: 0,
            rendezvous_timeout_tsc: RENDEZVOUS_TSC_BUDGET,
            device_ranges: Vec::new(),
        }
    }
}

unsafe fn phys_of(ptr: *mut c_void) -> u64 {
    unsafe { MmGetPhysicalAddress(ptr).QuadPart as u64 }
}

#[inline]
unsafe fn free_pool<T>(ptr: *mut T) {
    if !ptr.is_null() {
        unsafe { ExFreePoolWithTag(ptr.cast(), VMM_TAG) };
    }
}

fn valid_physical_allocation(
    virtual_address: usize,
    physical_address: u64,
    size: usize,
    alignment: usize,
    physical_bits: u8,
) -> bool {
    if alignment == 0
        || !alignment.is_power_of_two()
        || virtual_address & (alignment - 1) != 0
        || physical_address & (alignment as u64 - 1) != 0
    {
        return false;
    }
    let Some(limit) = 1u64.checked_shl(u32::from(physical_bits)) else {
        return false;
    };
    physical_address
        .checked_add(size as u64)
        .is_some_and(|end| end <= limit)
}

fn valid_vmx_allocation(pointer: *mut VmxRegion, physical: u64, physical_bits: u8) -> bool {
    valid_physical_allocation(
        pointer as usize,
        physical,
        VMX_REGION_SIZE,
        VMX_REGION_SIZE,
        physical_bits,
    )
}

pub struct Vcpu {
    pub(crate) vmcs: *mut VmxRegion,
    pub(crate) vmcs_pa: u64,
    pub(crate) vmxon: *mut VmxRegion,
    pub(crate) vmxon_pa: u64,

    pub(crate) msr_bitmap: *mut u8,
    pub(crate) msr_bitmap_pa: u64,
    pub(crate) host_stack: *mut u8,
    xsave_storage: *mut u8,
    pub(crate) xsave_area: *mut u8,
    pub(crate) xsave_size: u32,
    pub(crate) xsave_mask: u64,
    pub(crate) root_xcr0: u64,
    pub(crate) guest_xcr0: u64,
    pub(crate) root_cr3: u64,
    pub(crate) regs: GuestRegs,

    pub(crate) active_view: ActiveViewState,
    pub(crate) active_report: ActiveViewReport,
    pub(crate) mailbox: InternalMailbox,
    pub(crate) rendezvous_epoch: AtomicU64,
    pub(crate) run_id: u64,
    pub(crate) published_views: *const PublishedViewDirectory,
    pub(crate) events: *mut EventRing,
    pub(crate) emergency_event: EventRecord,
    pub(crate) fault_tracker: EptFaultTracker,
    pub(crate) allowed_fault_views: u64,
    pub(crate) guest_desc: Descriptors,
    pub(crate) host_desc: Descriptors,
    pub(crate) capabilities: IntelCapabilities,
    vmxon_permit: VmxonPermit,
    pub(crate) original_controls: OriginalControlRegisters,
    launch_error: Option<MonadError>,
    pub(crate) cpu: CpuId,
    // teardown waits for vmxoff before freeing this vcpu.
    active: AtomicBool,
}

// Page-sized pool allocations satisfy page alignment; the entire VCPU must fit.
const _: () = assert!(size_of::<Vcpu>() <= PAGE_SIZE);
const _: () = assert!(core::mem::align_of::<Vcpu>() <= PAGE_SIZE);

impl Vcpu {
    pub(crate) fn stamp_event(&self, event: EventRecord) -> EventRecord {
        event.with_provenance(self.run_id, self.rendezvous_epoch.load(Ordering::Acquire))
    }
}

pub(crate) struct ActiveViewReport {
    version: AtomicU64,
    slot: AtomicU16,
    generation: AtomicU64,
    eptp: AtomicU64,
}

impl ActiveViewReport {
    fn new(state: ActiveViewState) -> Self {
        Self {
            version: AtomicU64::new(0),
            slot: AtomicU16::new(state.id.slot),
            generation: AtomicU64::new(state.id.generation),
            eptp: AtomicU64::new(state.eptp),
        }
    }

    pub(crate) fn publish(&self, state: ActiveViewState) {
        self.version.fetch_add(1, Ordering::AcqRel);
        self.slot.store(state.id.slot, Ordering::Relaxed);
        self.generation
            .store(state.id.generation, Ordering::Relaxed);
        self.eptp.store(state.eptp, Ordering::Relaxed);
        self.version.fetch_add(1, Ordering::Release);
    }

    fn snapshot(&self) -> MonadResult<ActiveViewState> {
        for _ in 0..8 {
            let first = self.version.load(Ordering::Acquire);
            if first & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let state = ActiveViewState {
                id: ViewId {
                    slot: self.slot.load(Ordering::Relaxed),
                    reserved: 0,
                    generation: self.generation.load(Ordering::Relaxed),
                },
                eptp: self.eptp.load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            if self.version.load(Ordering::Relaxed) == first {
                return Ok(state);
            }
        }
        Err(MonadError::new(
            ErrorPhase::Activation,
            ErrorCode::RendezvousBusy,
            0,
        ))
    }
}

type ProductionViewManager = EptViewManager<WindowsPageAllocator>;

struct Vmm {
    // exallocatepool2 returns zeroed memory.
    cpu_count: u32,
    vcpus: *mut *mut Vcpu,
    manager: *mut ProductionViewManager,
    topology: CpuTopology,
    epoch: AtomicU64,
    rendezvous_tsc_budget: u64,
    aperture_end: u64,
    published_views: PublishedViewDirectory,
}

static VMM: AtomicPtr<Vmm> = AtomicPtr::new(null_mut());
static LIFECYCLE: Lifecycle = Lifecycle::new();

pub fn lifecycle_state() -> LifecycleState {
    LIFECYCLE.state()
}

struct StartTransition<'a> {
    control: &'a LifecycleControl<'a>,
    committed: bool,
}

impl Drop for StartTransition<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        match self.control.state() {
            LifecycleState::Preparing => {
                let _ = self
                    .control
                    .transition(LifecycleState::Preparing, LifecycleState::Absent);
            }
            LifecycleState::Launching => {
                let _ = self
                    .control
                    .transition(LifecycleState::Launching, LifecycleState::Absent);
            }
            _ => {}
        }
    }
}

unsafe fn init_vmxon(vcpu: *mut Vcpu) -> bool {
    let vmxon: *mut VmxRegion =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, VMX_REGION_SIZE as u64, VMM_TAG).cast() };

    if vmxon.is_null() {
        log::error!(
            "vmm.rs: ExAllocatePool2 failed: size={} tag={:#x}",
            VMX_REGION_SIZE,
            VMM_TAG,
        );
        return false;
    };

    let physical = unsafe { phys_of(vmxon.cast()) };
    if !valid_vmx_allocation(vmxon, physical, unsafe {
        (*vcpu).capabilities.max_physical_address_bits
    }) {
        unsafe { free_pool(vmxon) };
        return false;
    }

    unsafe {
        (*vmxon).header = (*vcpu).capabilities.vmx_revision_id;
        (*vcpu).vmxon = vmxon;
        (*vcpu).vmxon_pa = physical;
    }
    true
}

unsafe fn init_vmcs(vcpu: *mut Vcpu) -> bool {
    let vmcs: *mut VmxRegion =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, VMX_REGION_SIZE as u64, VMM_TAG).cast() };
    if vmcs.is_null() {
        log::error!(
            "vmm.rs: ExAllocatePool2 failed: size={} tag={:#x}",
            VMX_REGION_SIZE,
            VMM_TAG,
        );
        return false;
    };
    let physical = unsafe { phys_of(vmcs.cast()) };
    if !valid_vmx_allocation(vmcs, physical, unsafe {
        (*vcpu).capabilities.max_physical_address_bits
    }) {
        unsafe { free_pool(vmcs) };
        return false;
    }

    unsafe {
        (*vmcs).header = (*vcpu).capabilities.vmx_revision_id;
        (*vcpu).vmcs = vmcs;
        (*vcpu).vmcs_pa = physical;
    }
    true
}

unsafe fn init_msr_bitmap(vcpu: *mut Vcpu) -> bool {
    let msr_bitmap: *mut u8 =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE as u64, VMM_TAG).cast() };
    if msr_bitmap.is_null() {
        log::error!(
            "ExAllocatePool2 failed: size={} tag={:#x}",
            PAGE_SIZE,
            VMM_TAG
        );
        return false;
    }
    let physical = unsafe { phys_of(msr_bitmap.cast()) };
    if !valid_physical_allocation(
        msr_bitmap as usize,
        physical,
        PAGE_SIZE,
        PAGE_SIZE,
        unsafe { (*vcpu).capabilities.max_physical_address_bits },
    ) {
        unsafe { free_pool(msr_bitmap) };
        return false;
    }
    unsafe {
        core::ptr::write_bytes(msr_bitmap, 0, PAGE_SIZE);
        for msr in 0u32..=0x1fff {
            if crate::exit::msr::is_mtrr_write(msr) {
                let index = msr as usize;
                let byte = 2048 + index / 8;
                *msr_bitmap.add(byte) |= 1u8 << (index & 7);
            }
        }
        (*vcpu).msr_bitmap = msr_bitmap;
        (*vcpu).msr_bitmap_pa = physical;
    }
    true
}

unsafe fn init_host_stack(vcpu: *mut Vcpu) -> bool {
    let host_stack: *mut u8 =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, HOST_STACK_SIZE as u64, VMM_TAG).cast() };
    if host_stack.is_null() {
        log::error!(
            "ExAllocatePool2 failed: size={} tag={:#x}",
            HOST_STACK_SIZE,
            VMM_TAG
        );
        return false;
    }
    unsafe { (*vcpu).host_stack = host_stack };
    true
}

unsafe fn init_xsave_area(vcpu: *mut Vcpu) -> bool {
    let size = unsafe { (*vcpu).capabilities.xsave.maximum_size };
    let Some(allocation_size) = usize::try_from(size)
        .ok()
        .and_then(|value| value.checked_add(63))
    else {
        return false;
    };
    let storage: *mut u8 =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, allocation_size as u64, VMM_TAG).cast() };
    if storage.is_null() {
        return false;
    }
    let Some(storage_end) = (storage as usize).checked_add(allocation_size) else {
        unsafe { free_pool(storage) };
        return false;
    };
    let Some(aligned_address) = (storage as usize).checked_add(63).map(|value| value & !63) else {
        unsafe { free_pool(storage) };
        return false;
    };
    let Some(xsave_end) = aligned_address.checked_add(size as usize) else {
        unsafe { free_pool(storage) };
        return false;
    };
    if xsave_end > storage_end {
        unsafe { free_pool(storage) };
        return false;
    }
    let aligned = aligned_address as *mut u8;
    unsafe {
        core::ptr::write_bytes(aligned, 0, size as usize);
        (*vcpu).xsave_storage = storage;
        (*vcpu).xsave_area = aligned;
        (*vcpu).xsave_size = size;
        (*vcpu).xsave_mask = (*vcpu).capabilities.xsave.state_mask;
        (*vcpu).root_xcr0 = (*vcpu).capabilities.xsave.xcr0_mask;
    }
    true
}

unsafe fn alloc_vmm(
    manager: *mut ProductionViewManager,
    platform: &ValidatedPlatform,
    rendezvous_tsc_budget: u64,
    aperture_end: u64,
) -> *mut Vmm {
    let cpu_count = u32::from(platform.topology.len());

    let table_size = size_of::<*mut Vcpu>() * cpu_count as usize;

    let ctx: *mut Vmm =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, size_of::<Vmm>() as u64, VMM_TAG).cast() };
    let vcpus: *mut *mut Vcpu =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, table_size as u64, VMM_TAG).cast() };

    if ctx.is_null() || vcpus.is_null() {
        if ctx.is_null() {
            log::error!(
                "vmm.rs: ExAllocatePool2 failed: size={} tag={:#x}",
                size_of::<Vmm>(),
                VMM_TAG,
            );
        }
        if vcpus.is_null() {
            log::error!(
                "vmm.rs: ExAllocatePool2 failed: size={} tag={:#x}",
                table_size as u64,
                VMM_TAG,
            );
        }
        unsafe {
            free_pool(vcpus);
            free_pool(ctx);
        }
        return null_mut();
    }

    unsafe {
        (*ctx).cpu_count = cpu_count;
        (*ctx).vcpus = vcpus;
        (*ctx).manager = manager;
        (*ctx).topology = platform.topology;
        (*ctx).epoch = AtomicU64::new(0);
        (*ctx).rendezvous_tsc_budget = rendezvous_tsc_budget;
        (*ctx).aperture_end = aperture_end;
        (*ctx).published_views = PublishedViewDirectory::new();
    }

    ctx
}

unsafe fn init_vcpu(
    base_eptp: u64,
    platform: &ValidatedPlatform,
    cpu: CpuId,
    run_id: u64,
) -> *mut Vcpu {
    let vcpu: *mut Vcpu =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE as u64, VMM_TAG).cast() };
    if vcpu.is_null() {
        log::error!(
            "vmm.rs: ExAllocatePool2 failed: size={} tag={:#x}",
            size_of::<Vcpu>(),
            VMM_TAG,
        );
        return null_mut();
    };

    unsafe {
        (*vcpu).launch_error = None;
        (*vcpu).capabilities = platform.capabilities;
        (*vcpu).vmxon_permit = platform.vmxon_permit();
        (*vcpu).cpu = cpu;
        let base = ActiveViewState {
            id: crate::ept::ViewId {
                slot: 0,
                reserved: 0,
                generation: 1,
            },
            eptp: base_eptp,
        };
        (*vcpu).active_view = base;
        (*vcpu).active_report = ActiveViewReport::new(base);
        (*vcpu).mailbox = InternalMailbox::new();
        (*vcpu).rendezvous_epoch = AtomicU64::new(0);
        (*vcpu).run_id = run_id;
        (*vcpu).published_views = core::ptr::null();
        (*vcpu).events = core::ptr::null_mut();
        (*vcpu).emergency_event = EventRecord::zeroed();
        (*vcpu).fault_tracker = EptFaultTracker::new();
        (*vcpu).allowed_fault_views = COMPILED_ALLOWED_VIEW_MASK;
    }
    let vmxon_ok = unsafe { init_vmxon(vcpu) };
    let vmcs_ok = unsafe { init_vmcs(vcpu) };
    let msr_ok = unsafe { init_msr_bitmap(vcpu) };
    let host_stack_ok = unsafe { init_host_stack(vcpu) };
    let xsave_ok = unsafe { init_xsave_area(vcpu) };
    let events_ok = unsafe { init_event_ring(vcpu) };

    if !vmxon_ok || !vmcs_ok || !msr_ok || !host_stack_ok || !xsave_ok || !events_ok {
        unsafe {
            free_event_ring((*vcpu).events);
            free_pool((*vcpu).xsave_storage);
            free_pool((*vcpu).host_stack);
            free_pool((*vcpu).msr_bitmap);
            free_pool((*vcpu).vmcs);
            free_pool((*vcpu).vmxon);
            free_pool(vcpu);
        }
        return null_mut();
    }

    vcpu
}

unsafe fn free_vcpu(vcpu: *mut Vcpu) {
    if vcpu.is_null() {
        return;
    }

    unsafe {
        free_event_ring((*vcpu).events);
        free_pool((*vcpu).host_stack);
        free_pool((*vcpu).xsave_storage);
        free_pool((*vcpu).msr_bitmap);
        free_pool((*vcpu).vmcs);
        free_pool((*vcpu).vmxon);
        free_pool(vcpu);
    }
}

unsafe fn init_event_ring(vcpu: *mut Vcpu) -> bool {
    let ring = match EventRing::try_new() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let storage: *mut EventRing = unsafe {
        ExAllocatePool2(POOL_FLAG_NON_PAGED, size_of::<EventRing>() as u64, VMM_TAG).cast()
    };
    if storage.is_null() {
        return false;
    }
    unsafe {
        core::ptr::write(storage, ring);
        (*vcpu).events = storage;
    }
    true
}

unsafe fn free_event_ring(ring: *mut EventRing) {
    if !ring.is_null() {
        unsafe {
            core::ptr::drop_in_place(ring);
            free_pool(ring);
        }
    }
}

unsafe fn free_manager(manager: *mut ProductionViewManager) {
    if !manager.is_null() {
        unsafe {
            core::ptr::drop_in_place(manager);
            free_pool(manager);
        }
    }
}

pub fn read_events(
    cpu_dense_index: u16,
    after_sequence: u64,
    output: &mut [EventRecord],
) -> MonadResult<RingSnapshot> {
    let ctx = VMM.load(Ordering::Acquire);
    if ctx.is_null() || usize::from(cpu_dense_index) >= unsafe { (*ctx).cpu_count as usize } {
        return Err(MonadError::new(
            ErrorPhase::Telemetry,
            ErrorCode::InvalidCpuSet,
            u64::from(cpu_dense_index),
        ));
    }
    let vcpu = unsafe { *(*ctx).vcpus.add(usize::from(cpu_dense_index)) };
    let ring = if vcpu.is_null() {
        None
    } else {
        unsafe { (*vcpu).events.as_ref() }
    };
    ring.ok_or_else(|| {
        MonadError::new(
            ErrorPhase::Telemetry,
            ErrorCode::WrongObjectState,
            u64::from(cpu_dense_index),
        )
    })?
    .snapshot_from(after_sequence, output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicVcpuState {
    pub cpu_dense_index: u16,
    pub active: bool,
    pub active_view: crate::ept::ViewId,
    pub last_epoch: u64,
    pub last_fatal: u32,
    pub last_mailbox: u32,
    pub event_sequence: u64,
}

pub fn vcpu_state(cpu_dense_index: u16) -> MonadResult<PublicVcpuState> {
    let ctx = VMM.load(Ordering::Acquire);
    if ctx.is_null() || usize::from(cpu_dense_index) >= unsafe { (*ctx).cpu_count as usize } {
        return Err(MonadError::new(
            ErrorPhase::Telemetry,
            ErrorCode::InvalidCpuSet,
            u64::from(cpu_dense_index),
        ));
    }
    let vcpu = unsafe { *(*ctx).vcpus.add(usize::from(cpu_dense_index)) };
    if vcpu.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Telemetry,
            ErrorCode::WrongObjectState,
            u64::from(cpu_dense_index),
        ));
    }
    let event_sequence = unsafe {
        (*vcpu)
            .events
            .as_ref()
            .map(EventRing::latest_sequence)
            .unwrap_or(0)
    };
    Ok(PublicVcpuState {
        cpu_dense_index,
        active: unsafe { (*vcpu).active.load(Ordering::Acquire) },
        active_view: unsafe { (*vcpu).active_report.snapshot()? }.id,
        last_epoch: unsafe { (*vcpu).rendezvous_epoch.load(Ordering::Acquire) },
        last_fatal: unsafe { (*vcpu).emergency_event.status },
        last_mailbox: unsafe { (*vcpu).mailbox.status() },
        event_sequence,
    })
}

fn running_manager() -> MonadResult<*mut ProductionViewManager> {
    if lifecycle_state() != LifecycleState::Running {
        return Err(MonadError::new(
            ErrorPhase::Session,
            ErrorCode::InvalidLifecycleState,
            lifecycle_state() as u64,
        ));
    }
    let ctx = VMM.load(Ordering::Acquire);
    if ctx.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Session,
            ErrorCode::WrongObjectState,
            0,
        ));
    }
    let manager = unsafe { (*ctx).manager };
    if manager.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Session,
            ErrorCode::WrongObjectState,
            0,
        ));
    }
    Ok(manager)
}

/// allocates backing pages owned by the controller.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn allocate_backing(page_count: u32, immutable: bool) -> MonadResult<BackingId> {
    unsafe { &mut *running_manager()? }.allocate_backing(page_count, immutable)
}

/// writes bytes into mutable backing.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn write_backing(id: BackingId, offset: usize, data: &[u8]) -> MonadResult<()> {
    unsafe { &mut *running_manager()? }.write_backing(id, offset, data)
}

/// frees unreferenced backing.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn free_backing(id: BackingId) -> MonadResult<()> {
    unsafe { &mut *running_manager()? }.free_backing(id)
}

/// clones a published view into a draft.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn create_draft(source: ViewId) -> MonadResult<DraftId> {
    unsafe { &mut *running_manager()? }.create_draft(source)
}

/// applies the whole edit batch or leaves the draft alone.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn apply_edit_batch(id: DraftId, edits: &[DraftEdit]) -> MonadResult<()> {
    unsafe { &mut *running_manager()? }.apply_batch(id, edits)
}

/// drops a draft.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn discard_draft(id: DraftId) -> MonadResult<()> {
    unsafe { &mut *running_manager()? }.discard_draft(id)
}

/// checks a draft, publishes it, and pins its tables.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn publish_view(id: DraftId) -> MonadResult<ViewId> {
    let manager = running_manager()?;
    let view = unsafe { &mut *manager }.publish_draft(id)?;
    let eptp = unsafe { &*manager }.published_eptp(view)?;
    let ctx = VMM.load(Ordering::Acquire);
    unsafe { (*ctx).published_views.publish(view, eptp) }.map_err(|status| {
        MonadError::new(
            ErrorPhase::Publish,
            ErrorCode::EptVerificationFailure,
            status as u64,
        )
    })?;
    Ok(view)
}

/// walks an immutable view in software.
///
/// # Safety
///
/// the caller holds the controller serialization token at passive level.
pub unsafe fn query_view(id: ViewId, gpa: GuestPhysicalAddress) -> MonadResult<WalkResult> {
    unsafe { &*running_manager()? }.walk(id, gpa)
}

/// walks a draft in software.
///
/// # Safety
///
/// the caller holds the controller serialization token at passive level.
pub unsafe fn query_draft(id: DraftId, gpa: GuestPhysicalAddress) -> MonadResult<WalkResult> {
    unsafe { &*running_manager()? }.walk_draft(id, gpa)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicViewState {
    pub id: ViewId,
    pub metadata: ViewMetadata,
    pub active_cpu_set: [u64; 4],
}

impl Default for PublicViewState {
    fn default() -> Self {
        let id = ViewId {
            slot: 0,
            reserved: 0,
            generation: 0,
        };
        Self {
            id,
            metadata: ViewMetadata {
                source: id,
                edit_count: 0,
                table_pages: 0,
                leaf_1g: 0,
                leaf_2m: 0,
                leaf_4k: 0,
                backing_pages: 0,
                readable_pages: 0,
                writable_pages: 0,
                executable_pages: 0,
            },
            active_cpu_set: [0; 4],
        }
    }
}

/// copies public metadata for pinned views.
///
/// # Safety
///
/// the caller holds the controller serialization token at passive level.
pub unsafe fn list_views(output: &mut [PublicViewState]) -> MonadResult<(usize, usize)> {
    let manager = unsafe { &*running_manager()? };
    let mut ids = [ViewId {
        slot: 0,
        reserved: 0,
        generation: 0,
    }; crate::ept::MAX_PUBLISHED_VIEWS];
    let count = manager.published_ids(&mut ids);
    let copied = count.min(output.len());
    for index in 0..copied {
        output[index] = PublicViewState {
            id: ids[index],
            metadata: manager.metadata(ids[index])?,
            active_cpu_set: [0; 4],
        };
    }
    let ctx = VMM.load(Ordering::Acquire);
    for cpu_index in 0..unsafe { (*ctx).cpu_count as usize } {
        let vcpu = unsafe { *(*ctx).vcpus.add(cpu_index) };
        if vcpu.is_null() {
            continue;
        }
        let active = unsafe { (*vcpu).active_report.snapshot()? }.id;
        if let Some(view) = output[..copied].iter_mut().find(|view| view.id == active) {
            view.active_cpu_set[cpu_index / 64] |= 1u64 << (cpu_index % 64);
        }
    }
    Ok((copied, manager.published_count()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicCapabilities {
    pub capability_bits: u64,
    pub aperture_end: u64,
    pub max_physical_address_bits: u8,
    pub hypervisor_present: bool,
    pub cpu_count: u16,
}

fn encode_capability_bits(capabilities: &IntelCapabilities) -> u64 {
    u64::from(capabilities.ept.four_level_walk)
        | (u64::from(capabilities.ept.write_back_walk) << 1)
        | (u64::from(capabilities.ept.page_2m) << 2)
        | (u64::from(capabilities.ept.page_1g) << 3)
        | (u64::from(capabilities.ept.invept_single) << 4)
        | (u64::from(capabilities.ept.invept_all) << 5)
        | (u64::from(capabilities.ept.execute_only) << 6)
        | (u64::from(capabilities.ept.accessed_dirty) << 7)
}

pub fn inspect_capabilities() -> MonadResult<PublicCapabilities> {
    let hypervisor_present = cpuid(1, 0).ecx & (1 << 31) != 0;
    if hypervisor_present {
        return Ok(PublicCapabilities {
            capability_bits: 0,
            aperture_end: 0,
            max_physical_address_bits: 0,
            hypervisor_present: true,
            cpu_count: 0,
        });
    }
    let platform = collect_capabilities()?;
    let architectural_limit = 1u64 << platform.capabilities.max_physical_address_bits;
    Ok(PublicCapabilities {
        capability_bits: encode_capability_bits(&platform.capabilities),
        aperture_end: DEFAULT_APERTURE_END.min(architectural_limit),
        max_physical_address_bits: platform.capabilities.max_physical_address_bits,
        hypervisor_present: false,
        cpu_count: platform.topology.len(),
    })
}

pub fn current_capabilities() -> MonadResult<PublicCapabilities> {
    let ctx = VMM.load(Ordering::Acquire);
    if ctx.is_null() {
        return inspect_capabilities();
    }
    let first = unsafe { *(*ctx).vcpus };
    if first.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Capability,
            ErrorCode::WrongObjectState,
            0,
        ));
    }
    Ok(PublicCapabilities {
        capability_bits: encode_capability_bits(unsafe { &(*first).capabilities }),
        aperture_end: unsafe { (*ctx).aperture_end },
        max_physical_address_bits: unsafe { (*first).capabilities.max_physical_address_bits },
        hypervisor_present: false,
        cpu_count: unsafe { (*ctx).cpu_count as u16 },
    })
}

pub fn aperture_end() -> MonadResult<u64> {
    let manager = running_manager()?;
    unsafe { &*manager }.aperture_end()
}

/// switches the selected cpus to a pinned view as one transaction.
///
/// # Safety
///
/// caller holds the controller token at passive level.
pub unsafe fn activate_view(id: ViewId, cpu_set: &[CpuSetWord]) -> MonadResult<()> {
    let manager = unsafe { &*running_manager()? };
    let view = manager.published_view(id)?;
    unsafe { activate_published_view(view, cpu_set) }
}

unsafe fn free_vmm(ctx: *mut Vmm) {
    if ctx.is_null() {
        return;
    }

    unsafe {
        for i in 0..(*ctx).cpu_count {
            free_vcpu(*(*ctx).vcpus.add(i as usize));
        }
        free_manager((*ctx).manager);
        free_pool((*ctx).vcpus);
        free_pool(ctx);
    }
}

unsafe fn current_vcpu(ctx: *mut Vmm) -> *mut Vcpu {
    let mut current = unsafe { core::mem::zeroed::<PROCESSOR_NUMBER>() };
    unsafe { KeGetCurrentProcessorNumberEx(&mut current) };
    for i in 0..unsafe { (*ctx).cpu_count } {
        let vcpu = unsafe { *(*ctx).vcpus.add(i as usize) };
        if !vcpu.is_null()
            && unsafe { (*vcpu).cpu.group == current.Group }
            && unsafe { (*vcpu).cpu.number == current.Number }
        {
            return vcpu;
        }
    }
    null_mut()
}

unsafe extern "C" fn shutdown_cpu(context: u64) -> u64 {
    let ctx = context as *mut Vmm;
    if ctx.is_null() {
        return 0;
    }
    let vcpu = unsafe { current_vcpu(ctx) };
    if vcpu.is_null() || !unsafe { (*vcpu).active.load(Ordering::Acquire) } {
        return 1;
    }

    // safety: this is the registered ipi callback and the mailbox is prepared.
    unsafe { rendezvous_vmcall() };
    u64::from(!unsafe { (*vcpu).active.load(Ordering::Acquire) })
}

unsafe fn shutdown_all(ctx: *mut Vmm) -> bool {
    if ctx.is_null() {
        return true;
    }
    let epoch = match unsafe { (*ctx).epoch.fetch_add(1, Ordering::AcqRel) }.checked_add(1) {
        Some(epoch) if epoch != 0 => epoch,
        _ => return false,
    };
    for i in 0..unsafe { (*ctx).cpu_count } {
        let vcpu = unsafe { *(*ctx).vcpus.add(i as usize) };
        if vcpu.is_null() || !unsafe { (*vcpu).active.load(Ordering::Acquire) } {
            continue;
        }
        if unsafe { (*vcpu).mailbox.state() }
            .is_some_and(|state| state != crate::rendezvous::MailboxState::Idle)
        {
            let _ = unsafe { (*vcpu).mailbox.reset() };
        }
        unsafe { (*vcpu).rendezvous_epoch.store(epoch, Ordering::Release) };
        let active = match unsafe { (*vcpu).active_report.snapshot() } {
            Ok(value) => value,
            Err(_) => return false,
        };
        if unsafe {
            (*vcpu).mailbox.prepare(MailboxRequest {
                epoch,
                operation: RendezvousOperation::Shutdown,
                target_view: active.id,
                target_eptp: active.eptp,
                expected_old_eptp: active.eptp,
            })
        }
        .is_err()
        {
            return false;
        }
    }
    unsafe { KeIpiGenericCall(Some(shutdown_cpu), ctx as u64) };

    for i in 0..unsafe { (*ctx).cpu_count } {
        let vcpu = unsafe { *(*ctx).vcpus.add(i as usize) };
        if !vcpu.is_null() && unsafe { (*vcpu).active.load(Ordering::Acquire) } {
            return false;
        }
    }
    true
}

struct ActivationContext {
    vmm: *mut Vmm,
    transaction: *const RendezvousTransaction,
    target: ActiveViewState,
    old: [ActiveViewState; crate::topology::MAX_LOGICAL_CPUS],
}

#[cfg(not(test))]
fn fatal_rendezvous(cpu: u16, detail: u64) -> ! {
    // safety: this terminal path uses stable monad bugcheck parameters.
    unsafe {
        KeBugCheckEx(
            MONAD_BUGCHECK_CODE,
            FatalReason::InvalidVcpuState as u64,
            u64::from(cpu),
            detail,
            0,
        )
    }
}

unsafe extern "C" fn activate_cpu(context: u64) -> u64 {
    let activation = context as *const ActivationContext;
    if activation.is_null() {
        return 0;
    }
    let activation = unsafe { &*activation };
    let transaction = unsafe { &*activation.transaction };
    let vcpu = unsafe { current_vcpu(activation.vmm) };
    if vcpu.is_null() {
        transaction.fatal.store(true, Ordering::Release);
        return 0;
    }
    let dense = unsafe { (*vcpu).cpu.dense_index };
    transaction.arrived.fetch_add(1, Ordering::AcqRel);
    if !transaction.wait_for(&transaction.arrived, read_tsc) {
        #[cfg(not(test))]
        fatal_rendezvous(dense, 1);
        #[cfg(test)]
        return 0;
    }

    if transaction.is_target(dense) {
        // safety: passive control prepared this vcpu's mailbox.
        unsafe { rendezvous_vmcall() };
        let switched = unsafe { (*vcpu).active_view == activation.target };
        let status = unsafe { (*vcpu).mailbox.status() };
        if switched {
            transaction.set_result(dense, CpuResultState::Switched, status);
        } else {
            transaction.set_result(dense, CpuResultState::Failed, status);
            transaction.failed.store(true, Ordering::Release);
        }
    } else {
        transaction.set_result(dense, CpuResultState::NotTarget, 0);
    }

    transaction.finished.fetch_add(1, Ordering::AcqRel);
    if !transaction.wait_for(&transaction.finished, read_tsc) {
        #[cfg(not(test))]
        fatal_rendezvous(dense, 2);
        #[cfg(test)]
        return 0;
    }

    if transaction.failed.load(Ordering::Acquire)
        && transaction.is_target(dense)
        && unsafe { (*vcpu).active_view == activation.target }
    {
        let old = activation.old[usize::from(dense)];
        if unsafe { (*vcpu).mailbox.reset() }.is_err()
            || unsafe {
                (*vcpu).mailbox.prepare(MailboxRequest {
                    epoch: transaction.epoch,
                    operation: RendezvousOperation::RollbackView,
                    target_view: old.id,
                    target_eptp: old.eptp,
                    expected_old_eptp: activation.target.eptp,
                })
            }
            .is_err()
        {
            transaction.fatal.store(true, Ordering::Release);
        } else {
            // safety: this callback owns the matching prepared mailbox.
            unsafe { rendezvous_vmcall() };
            if unsafe { (*vcpu).active_view } != old {
                transaction.fatal.store(true, Ordering::Release);
                transaction.set_result(dense, CpuResultState::Fatal, 0);
            } else {
                transaction.set_result(dense, CpuResultState::RolledBack, 0);
            }
        }
    }

    transaction.rollback_finished.fetch_add(1, Ordering::AcqRel);
    if !transaction.wait_for(&transaction.rollback_finished, read_tsc)
        || transaction.fatal.load(Ordering::Acquire)
    {
        #[cfg(not(test))]
        fatal_rendezvous(dense, 3);
        #[cfg(test)]
        return 0;
    }
    transaction.release.store(true, Ordering::Release);
    1
}

/// switches the selected processors to a pinned view.
///
/// # Safety
///
/// the caller runs at `PASSIVE_LEVEL`, keeps `view` pinned through vmm teardown,
/// and serializes publication and lifecycle requests.
pub unsafe fn activate_published_view<A: crate::ept::EptPageAllocator + Clone>(
    view: &crate::ept::PublishedView<A>,
    cpu_set: &[CpuSetWord],
) -> MonadResult<()> {
    let _lifecycle_guard = LIFECYCLE
        .try_control()
        .map_err(|_| MonadError::new(ErrorPhase::Activation, ErrorCode::RendezvousBusy, 0))?;
    if _lifecycle_guard.state() != LifecycleState::Running {
        return Err(MonadError::new(
            ErrorPhase::Activation,
            ErrorCode::InvalidLifecycleState,
            _lifecycle_guard.state() as u64,
        ));
    }
    let ctx = VMM.load(Ordering::Acquire);
    if ctx.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Activation,
            ErrorCode::InvalidLifecycleState,
            0,
        ));
    }
    let cpu_count = unsafe { (*ctx).cpu_count };
    let mut virtualized = [false; crate::topology::MAX_LOGICAL_CPUS];
    for index in 0..cpu_count {
        let vcpu = unsafe { *(*ctx).vcpus.add(index as usize) };
        virtualized[index as usize] =
            !vcpu.is_null() && unsafe { (*vcpu).active.load(Ordering::Acquire) };
    }
    let selection = unsafe { (*ctx).topology.validate_cpu_set(cpu_set, &virtualized) }?;
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(usize::from(selection.len()))
        .map_err(|_| {
            MonadError::new(
                ErrorPhase::Activation,
                ErrorCode::AllocationFailure,
                u64::from(selection.len()),
            )
        })?;
    for index in 0..cpu_count as u16 {
        if selection.contains(index) {
            targets.push(index);
        }
    }
    let epoch = unsafe { (*ctx).epoch.fetch_add(1, Ordering::AcqRel) }
        .checked_add(1)
        .filter(|epoch| *epoch != 0)
        .ok_or_else(|| {
            MonadError::new(
                ErrorPhase::Activation,
                ErrorCode::GenerationOverflow,
                u64::MAX,
            )
        })?;
    let now = read_tsc();
    let deadline = now
        .checked_add(unsafe { (*ctx).rendezvous_tsc_budget })
        .ok_or_else(|| MonadError::new(ErrorPhase::Activation, ErrorCode::AddressOverflow, now))?;
    let transaction = RendezvousTransaction::new(epoch, cpu_count as u16, &targets, deadline)?;
    let target = ActiveViewState {
        id: view.id(),
        eptp: view.eptp(),
    };
    let mut activation = ActivationContext {
        vmm: ctx,
        transaction: core::ptr::from_ref(&transaction),
        target,
        old: [target; crate::topology::MAX_LOGICAL_CPUS],
    };
    if unsafe { (*ctx).published_views.resolve(target.id) }.is_none() {
        unsafe { (*ctx).published_views.publish(target.id, target.eptp) }.map_err(|status| {
            MonadError::new(
                ErrorPhase::Activation,
                ErrorCode::WrongObjectState,
                status as u64,
            )
        })?;
    }
    for index in 0..cpu_count as u16 {
        let vcpu = unsafe { *(*ctx).vcpus.add(usize::from(index)) };
        let old = unsafe { (*vcpu).active_report.snapshot()? };
        activation.old[usize::from(index)] = old;
        unsafe { (*vcpu).rendezvous_epoch.store(epoch, Ordering::Release) };
        if selection.contains(index) {
            if unsafe { (*vcpu).mailbox.state() }
                .is_some_and(|state| state != crate::rendezvous::MailboxState::Idle)
            {
                unsafe { (*vcpu).mailbox.reset() }.map_err(|status| {
                    MonadError::new(
                        ErrorPhase::Activation,
                        ErrorCode::WrongObjectState,
                        status as u64,
                    )
                })?;
            }
            unsafe {
                (*vcpu).mailbox.prepare(MailboxRequest {
                    epoch,
                    operation: RendezvousOperation::SwitchView,
                    target_view: target.id,
                    target_eptp: target.eptp,
                    expected_old_eptp: old.eptp,
                })
            }
            .map_err(|status| {
                MonadError::new(
                    ErrorPhase::Activation,
                    ErrorCode::WrongObjectState,
                    status as u64,
                )
                .on_cpu(index)
            })?;
        }
    }
    unsafe {
        KeIpiGenericCall(
            Some(activate_cpu),
            core::ptr::from_mut(&mut activation) as u64,
        )
    };
    if transaction.fatal.load(Ordering::Acquire) {
        return Err(MonadError::new(
            ErrorPhase::Activation,
            ErrorCode::ActivationRolledBack,
            1,
        ));
    }
    if transaction.failed.load(Ordering::Acquire) {
        return Err(MonadError::new(
            ErrorPhase::Activation,
            ErrorCode::ActivationRolledBack,
            0,
        ));
    }
    Ok(())
}

unsafe fn activate_base(ctx: *mut Vmm) -> MonadResult<()> {
    let cpu_count = unsafe { (*ctx).cpu_count as u16 };
    let base_id = crate::ept::ViewId {
        slot: 0,
        reserved: 0,
        generation: 1,
    };
    let base_eptp = unsafe { (*ctx).published_views.resolve(base_id) }.ok_or_else(|| {
        MonadError::new(ErrorPhase::Shutdown, ErrorCode::EptVerificationFailure, 0)
    })?;
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(usize::from(cpu_count))
        .map_err(|_| {
            MonadError::new(
                ErrorPhase::Shutdown,
                ErrorCode::AllocationFailure,
                u64::from(cpu_count),
            )
        })?;
    targets.extend(0..cpu_count);
    let epoch = unsafe { (*ctx).epoch.fetch_add(1, Ordering::AcqRel) }
        .checked_add(1)
        .filter(|epoch| *epoch != 0)
        .ok_or_else(|| {
            MonadError::new(
                ErrorPhase::Shutdown,
                ErrorCode::GenerationOverflow,
                u64::MAX,
            )
        })?;
    let now = read_tsc();
    let deadline = now
        .checked_add(unsafe { (*ctx).rendezvous_tsc_budget })
        .ok_or_else(|| MonadError::new(ErrorPhase::Shutdown, ErrorCode::AddressOverflow, now))?;
    let transaction = RendezvousTransaction::new(epoch, cpu_count, &targets, deadline)?;
    let target = ActiveViewState {
        id: base_id,
        eptp: base_eptp,
    };
    let mut activation = ActivationContext {
        vmm: ctx,
        transaction: core::ptr::from_ref(&transaction),
        target,
        old: [target; crate::topology::MAX_LOGICAL_CPUS],
    };
    for index in 0..cpu_count {
        let vcpu = unsafe { *(*ctx).vcpus.add(usize::from(index)) };
        let old = unsafe { (*vcpu).active_report.snapshot()? };
        activation.old[usize::from(index)] = old;
        unsafe { (*vcpu).rendezvous_epoch.store(epoch, Ordering::Release) };
        if unsafe { (*vcpu).mailbox.state() }
            .is_some_and(|state| state != crate::rendezvous::MailboxState::Idle)
        {
            unsafe { (*vcpu).mailbox.reset() }.map_err(|status| {
                MonadError::new(
                    ErrorPhase::Shutdown,
                    ErrorCode::WrongObjectState,
                    status as u64,
                )
            })?;
        }
        unsafe {
            (*vcpu).mailbox.prepare(MailboxRequest {
                epoch,
                operation: RendezvousOperation::SwitchView,
                target_view: target.id,
                target_eptp: target.eptp,
                expected_old_eptp: old.eptp,
            })
        }
        .map_err(|status| {
            MonadError::new(
                ErrorPhase::Shutdown,
                ErrorCode::WrongObjectState,
                status as u64,
            )
            .on_cpu(index)
        })?;
    }
    unsafe {
        KeIpiGenericCall(
            Some(activate_cpu),
            core::ptr::from_mut(&mut activation) as u64,
        )
    };
    if transaction.failed.load(Ordering::Acquire) || transaction.fatal.load(Ordering::Acquire) {
        return Err(MonadError::new(
            ErrorPhase::Shutdown,
            ErrorCode::ActivationRolledBack,
            0,
        ));
    }
    Ok(())
}

struct LaunchContext {
    vmm: *mut Vmm,
    epoch: u64,
    participant_count: u32,
    arrived: AtomicU32,
    rollback_finished: AtomicU32,
    failed: AtomicBool,
    fatal: AtomicBool,
    deadline_tsc: u64,
}

fn wait_launch_barrier(counter: &AtomicU32, launch: &LaunchContext) -> bool {
    while counter.load(Ordering::Acquire) != launch.participant_count {
        if read_tsc() >= launch.deadline_tsc {
            launch.fatal.store(true, Ordering::Release);
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

unsafe extern "C" fn launch_cpu(context: u64) -> u64 {
    let launch = context as *const LaunchContext;
    if launch.is_null() {
        return 0;
    }
    let launch = unsafe { &*launch };
    let vcpu = unsafe { current_vcpu(launch.vmm) };
    if vcpu.is_null() {
        launch.failed.store(true, Ordering::Release);
    } else {
        let dense = unsafe { (*vcpu).cpu.dense_index };
        if let Err(error) = unsafe { init_cpu(vcpu, u32::from(dense)) } {
            unsafe {
                (*vcpu).launch_error = Some(error);
            }
            launch.failed.store(true, Ordering::Release);
        }
    }
    launch.arrived.fetch_add(1, Ordering::AcqRel);
    if !wait_launch_barrier(&launch.arrived, launch) {
        #[cfg(not(test))]
        fatal_rendezvous(
            if vcpu.is_null() {
                u16::MAX
            } else {
                unsafe { (*vcpu).cpu.dense_index }
            },
            4,
        );
        #[cfg(test)]
        return 0;
    }
    if launch.failed.load(Ordering::Acquire)
        && !vcpu.is_null()
        && unsafe { (*vcpu).active.load(Ordering::Acquire) }
    {
        let active = unsafe { (*vcpu).active_view };
        unsafe {
            (*vcpu)
                .rendezvous_epoch
                .store(launch.epoch, Ordering::Release)
        };
        if unsafe {
            (*vcpu).mailbox.prepare(MailboxRequest {
                epoch: launch.epoch,
                operation: RendezvousOperation::Shutdown,
                target_view: active.id,
                target_eptp: active.eptp,
                expected_old_eptp: active.eptp,
            })
        }
        .is_err()
        {
            launch.fatal.store(true, Ordering::Release);
        } else {
            // safety: this callback owns the prepared rollback mailbox.
            unsafe { rendezvous_vmcall() };
            if unsafe { (*vcpu).active.load(Ordering::Acquire) } {
                launch.fatal.store(true, Ordering::Release);
            }
        }
    }
    launch.rollback_finished.fetch_add(1, Ordering::AcqRel);
    if !wait_launch_barrier(&launch.rollback_finished, launch)
        || launch.fatal.load(Ordering::Acquire)
    {
        #[cfg(not(test))]
        fatal_rendezvous(
            if vcpu.is_null() {
                u16::MAX
            } else {
                unsafe { (*vcpu).cpu.dense_index }
            },
            5,
        );
        #[cfg(test)]
        return 0;
    }
    1
}

/// stops all vcpus and frees vmm-owned state.
///
/// # Safety
///
/// the caller runs at `PASSIVE_LEVEL` and does not independently change vmx
/// state on these processors. it must prevent new hypervisor client work from
/// beginning during driver teardown.
pub unsafe fn vmm_shutdown() -> MonadResult<()> {
    let lifecycle_guard = LIFECYCLE.try_control()?;

    let ctx = VMM.load(Ordering::Acquire);
    if ctx.is_null() {
        return if lifecycle_guard.state() == LifecycleState::Absent {
            Ok(())
        } else {
            Err(MonadError::new(
                ErrorPhase::Shutdown,
                ErrorCode::InvalidLifecycleState,
                lifecycle_guard.state() as u64,
            ))
        };
    }

    lifecycle_guard.transition(LifecycleState::Running, LifecycleState::Quiescing)?;
    if let Err(error) = unsafe { activate_base(ctx) } {
        lifecycle_guard.transition(LifecycleState::Quiescing, LifecycleState::Running)?;
        return Err(error);
    }
    lifecycle_guard.transition(LifecycleState::Quiescing, LifecycleState::Stopping)?;

    if !unsafe { shutdown_all(ctx) } {
        LIFECYCLE.enter_fatal();
        #[cfg(not(test))]
        fatal_rendezvous(u16::MAX, FatalReason::PartialShutdown as u64);
        #[cfg(test)]
        return Err(MonadError::new(
            ErrorPhase::Shutdown,
            ErrorCode::ShutdownFailure,
            0,
        ));
    }

    VMM.store(null_mut(), Ordering::Release);
    unsafe { free_vmm(ctx) };
    lifecycle_guard.transition(LifecycleState::Stopping, LifecycleState::Absent)?;
    Ok(())
}

/// starts the vmm on the startup cpu snapshot. later cpus stay native.
///
/// # Safety
///
/// the caller runs at `PASSIVE_LEVEL` and exclusively owns vmx startup.
pub unsafe fn vmm_init(config: VmmStartConfig) -> MonadResult<()> {
    let lifecycle_guard = LIFECYCLE.try_control()?;
    lifecycle_guard.transition(LifecycleState::Absent, LifecycleState::Preparing)?;
    let mut start_transition = StartTransition {
        control: &lifecycle_guard,
        committed: false,
    };

    if !VMM.load(Ordering::Acquire).is_null() {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::InvalidLifecycleState,
            0,
        ));
    }

    if config.session_nonce == 0 || config.rendezvous_timeout_tsc == 0 {
        return Err(MonadError::new(
            ErrorPhase::Session,
            ErrorCode::WrongSession,
            0,
        ));
    }
    let platform = collect_capabilities()?;
    let root_cr3 = crate::arch::intel::state::system_cr3()?;
    let architectural_limit = 1u64 << platform.capabilities.max_physical_address_bits;
    let configured_limit = if config.aperture_limit == 0 {
        DEFAULT_APERTURE_END.min(architectural_limit)
    } else {
        config.aperture_limit
    };
    if configured_limit == 0
        || configured_limit > architectural_limit
        || configured_limit & (crate::ept::PAGE_SIZE_4K - 1) != 0
    {
        return Err(MonadError::new(
            ErrorPhase::EptBuild,
            ErrorCode::InvalidRange,
            configured_limit,
        ));
    }
    let (physical_ranges, required_ranges) = collect_physical_inventory(&config.device_ranges)?;
    let inventory = PhysicalInventory::ingest(
        &physical_ranges,
        &required_ranges,
        platform.capabilities.max_physical_address_bits,
        Some(configured_limit),
    )?;
    let aperture_end = inventory.aperture_end();
    let raw_mtrrs = collect_raw_mtrr_state(platform.capabilities.max_physical_address_bits)?;
    let memory_types = normalize_mtrrs(&raw_mtrrs, aperture_end)?;
    let base = build_base_view(
        WindowsPageAllocator,
        inventory,
        memory_types,
        platform.capabilities.max_physical_address_bits,
        platform.capabilities.ept.page_1g,
        platform.capabilities.ept.page_2m,
        platform.capabilities.ept.execute_only,
    )?;
    let manager_value = EptViewManager::new(
        base,
        WindowsPageAllocator,
        config.session_nonce,
        platform.capabilities.max_physical_address_bits,
    )?;
    let base_id = ViewId {
        slot: 0,
        reserved: 0,
        generation: 1,
    };
    let base_eptp = manager_value.published_eptp(base_id)?;
    let manager: *mut ProductionViewManager = unsafe {
        ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            size_of::<ProductionViewManager>() as u64,
            VMM_TAG,
        )
        .cast()
    };
    if manager.is_null() {
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::AllocationFailure,
            0,
        ));
    }
    unsafe { core::ptr::write(manager, manager_value) };

    let ctx: *mut Vmm = unsafe {
        alloc_vmm(
            manager,
            &platform,
            config.rendezvous_timeout_tsc,
            aperture_end,
        )
    };
    if ctx.is_null() {
        unsafe { free_manager(manager) };
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::AllocationFailure,
            0,
        ));
    }
    let cpu_count = unsafe { (*ctx).cpu_count };
    if unsafe { (*ctx).published_views.publish(base_id, base_eptp) }.is_err() {
        unsafe { free_vmm(ctx) };
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::EptVerificationFailure,
            0,
        ));
    }

    // allocate every vcpu before starting vmx.
    let mut alloc_failed = false;
    for i in 0..cpu_count {
        let Some(cpu) = (unsafe { (*ctx).topology.get(i as u16) }) else {
            unsafe { free_vmm(ctx) };
            return Err(MonadError::new(
                ErrorPhase::Topology,
                ErrorCode::TopologyChanged,
                u64::from(i),
            ));
        };
        let vcpu = unsafe { init_vcpu(base_eptp, &platform, cpu, config.session_nonce) };
        alloc_failed |= vcpu.is_null();
        if vcpu.is_null() {
            log::error!("vcpu alloc failed for processor {}", i);
        }
        unsafe {
            if !vcpu.is_null() {
                (*vcpu).root_cr3 = root_cr3;
                (*vcpu).published_views = core::ptr::from_ref(&(*ctx).published_views);
            }
            *(*ctx).vcpus.add(i as usize) = vcpu;
        }
    }

    if alloc_failed {
        unsafe { free_vmm(ctx) };
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::AllocationFailure,
            0,
        ));
    }

    // last topology check before vmxon.
    match snapshot_active_processors() {
        Ok(topology) if unsafe { (*ctx).topology.same_identity(&topology) } => {}
        Ok(_) => {
            log::error!("processor topology changed during preparation");
            unsafe { free_vmm(ctx) };
            return Err(MonadError::new(
                ErrorPhase::Topology,
                ErrorCode::TopologyChanged,
                0,
            ));
        }
        Err(error) => {
            log::error!("processor topology revalidation failed: {error:?}");
            unsafe { free_vmm(ctx) };
            return Err(error);
        }
    }

    let epoch = unsafe { (*ctx).epoch.fetch_add(1, Ordering::AcqRel) }
        .checked_add(1)
        .filter(|epoch| *epoch != 0)
        .ok_or_else(|| {
            unsafe { free_vmm(ctx) };
            MonadError::new(ErrorPhase::Launch, ErrorCode::GenerationOverflow, u64::MAX)
        })?;
    let now = read_tsc();
    let deadline_tsc = now
        .checked_add(unsafe { (*ctx).rendezvous_tsc_budget })
        .ok_or_else(|| {
            unsafe { free_vmm(ctx) };
            MonadError::new(ErrorPhase::Launch, ErrorCode::AddressOverflow, now)
        })?;
    start_transition
        .control
        .transition(LifecycleState::Preparing, LifecycleState::Launching)?;
    let mut launch = LaunchContext {
        vmm: ctx,
        epoch,
        participant_count: cpu_count,
        arrived: AtomicU32::new(0),
        rollback_finished: AtomicU32::new(0),
        failed: AtomicBool::new(false),
        fatal: AtomicBool::new(false),
        deadline_tsc,
    };
    unsafe { KeIpiGenericCall(Some(launch_cpu), core::ptr::from_mut(&mut launch) as u64) };
    if launch.fatal.load(Ordering::Acquire) {
        unsafe { free_vmm(ctx) };
        return Err(MonadError::new(
            ErrorPhase::Launch,
            ErrorCode::LaunchRollbackFailure,
            1,
        ));
    }
    if launch.failed.load(Ordering::Acquire) {
        let error =
            (0..cpu_count).find_map(|i| unsafe { (**(*ctx).vcpus.add(i as usize)).launch_error });
        if let Some(error) = error {
            log::error!("launch failed: {error:?}");
        }
        unsafe { free_vmm(ctx) };
        return Err(error.unwrap_or_else(|| {
            MonadError::new(ErrorPhase::Launch, ErrorCode::VmxInstructionFailure, 0)
        }));
    }

    start_transition
        .control
        .transition(LifecycleState::Launching, LifecycleState::Running)?;
    VMM.store(ctx, Ordering::Release);
    start_transition.committed = true;
    Ok(())
}

unsafe fn vmxoff_or_fatal(vcpu: *mut Vcpu) {
    if vmxoff().is_err() {
        unsafe { fatal_vmexit(vcpu, FatalReason::PartialShutdown) }
    }
}

unsafe fn stop_cpu(vcpu: *mut Vcpu) -> ! {
    let state = (
        vmread(vmcs::guest::RIP),
        vmread(vmcs::guest::RSP),
        vmread(vmcs::guest::RFLAGS),
        vmread(vmcs::guest::CR0),
        vmread(vmcs::guest::CR3),
        vmread(vmcs::guest::CR4),
        vmread(vmcs::guest::DR7),
        vmread(vmcs::guest::IA32_SYSENTER_CS),
        vmread(vmcs::guest::IA32_SYSENTER_ESP),
        vmread(vmcs::guest::IA32_SYSENTER_EIP),
        vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN),
        vmread(vmcs::guest::CS_SELECTOR),
    );

    let (
        rip,
        rsp,
        rflags,
        guest_cr0,
        guest_cr3,
        guest_cr4,
        guest_dr7,
        guest_sysenter_cs,
        guest_sysenter_esp,
        guest_sysenter_eip,
        instruction_length,
        guest_cs,
    ) = match state {
        (
            Ok(rip),
            Ok(rsp),
            Ok(rflags),
            Ok(cr0),
            Ok(cr3),
            Ok(cr4),
            Ok(dr7),
            Ok(sysenter_cs),
            Ok(sysenter_esp),
            Ok(sysenter_eip),
            Ok(instruction_length),
            Ok(guest_cs),
        ) => (
            rip,
            rsp,
            rflags,
            cr0,
            cr3,
            cr4,
            dr7,
            sysenter_cs,
            sysenter_esp,
            sysenter_eip,
            instruction_length,
            guest_cs,
        ),
        _ => unsafe { fatal_vmexit(vcpu, FatalReason::VmreadFailure) },
    };

    let (trampoline_start, trampoline_end) = rendezvous_vmcall_bounds();
    let origin = ShutdownOrigin {
        cpl: (guest_cs & 3) as u8,
        rip,
        trampoline_start,
        trampoline_end,
        expected_epoch: unsafe { (*vcpu).rendezvous_epoch.load(Ordering::Acquire) },
        mailbox_epoch: unsafe { (*vcpu).mailbox.epoch() },
        expected_cpu: unsafe { (*vcpu).cpu.dense_index },
        current_cpu: unsafe { (*vcpu).cpu.dense_index },
    };
    if validate_shutdown_origin(origin).is_err() {
        unsafe { fatal_vmexit(vcpu, FatalReason::InvalidInternalMailbox) }
    }
    let next_rip = match rip.checked_add(instruction_length) {
        Some(value) if value <= trampoline_end => value,
        _ => unsafe { fatal_vmexit(vcpu, FatalReason::InvalidInternalMailbox) },
    };

    unsafe {
        (*vcpu).regs.rip = next_rip;
        (*vcpu).regs.rsp = rsp;
        (*vcpu).regs.rflags = rflags;
    }

    let native = match NativeReturnState::capture(vmread) {
        Ok(state) => state,
        Err(_) => unsafe { fatal_vmexit(vcpu, FatalReason::InvalidVcpuState) },
    };
    unsafe { vmxoff_or_fatal(vcpu) };

    // vmxoff makes this vcpu unreachable to hardware.
    unsafe { (*vcpu).active.store(false, Ordering::Release) };

    unsafe {
        write_msr(IA32_SYSENTER_CS, guest_sysenter_cs);
        write_msr(IA32_SYSENTER_ESP, guest_sysenter_esp);
        write_msr(IA32_SYSENTER_EIP, guest_sysenter_eip);
        write_cr3(guest_cr3);
        write_cr4((guest_cr4 & !(1 << 13)) | ((*vcpu).original_controls.cr4 & (1 << 13)));
        native.restore();
        // DR0-3/6 stay live throughout root execution; startup values are obsolete.
        write_dr7(guest_dr7);
    }

    unsafe {
        restore_guest(
            &(*vcpu).regs,
            (*vcpu).xsave_area,
            (*vcpu).xsave_mask,
            (*vcpu).guest_xcr0,
            guest_cr0,
        )
    }
}

#[cfg(not(test))]
unsafe fn fatal_vmexit(vcpu: *mut Vcpu, reason: FatalReason) -> ! {
    LIFECYCLE.enter_fatal();
    let (group, number) = if vcpu.is_null() {
        (u16::MAX, u8::MAX)
    } else {
        unsafe { ((*vcpu).cpu.group, (*vcpu).cpu.number) }
    };
    unsafe {
        KeBugCheckEx(
            MONAD_BUGCHECK_CODE,
            reason as u64,
            u64::from(group),
            u64::from(number),
            0,
        )
    }
}

#[cfg(test)]
unsafe fn fatal_vmexit(_vcpu: *mut Vcpu, reason: FatalReason) -> ! {
    panic!("fatal VM exit during a unit test: {reason:?}")
}

#[unsafe(no_mangle)]
/// runs the root vm-exit loop for this vcpu.
///
/// # Safety
///
/// monad's vm-exit assembly enters on `vcpu`'s root stack. that live vcpu is
/// exclusively owned and its vmcs is current.
pub(crate) unsafe extern "win64" fn vmexit_handler(vcpu: *mut Vcpu) -> ! {
    loop {
        match unsafe { handle(&mut *vcpu) } {
            VmExitAction::Resume => {}
            VmExitAction::Shutdown => unsafe { stop_cpu(vcpu) },
            VmExitAction::Fatal(reason) => unsafe { fatal_vmexit(vcpu, reason) },
        }

        if unsafe { vmresume(&mut (*vcpu).regs) }.is_err() {
            unsafe { fatal_vmexit(vcpu, FatalReason::VmEntryFailure) }
        }
    }
}

unsafe fn init_cpu(vcpu: *mut Vcpu, cpu: u32) -> MonadResult<()> {
    let cpu_index = cpu as u16;
    if vcpu.is_null() {
        return Err(
            MonadError::new(ErrorPhase::Launch, ErrorCode::InvalidLifecycleState, 0)
                .on_cpu(cpu_index),
        );
    }

    let mut current = unsafe { core::mem::zeroed::<PROCESSOR_NUMBER>() };
    unsafe { KeGetCurrentProcessorNumberEx(&mut current) };
    if current.Group != unsafe { (*vcpu).cpu.group }
        || current.Number != unsafe { (*vcpu).cpu.number }
    {
        return Err(MonadError::new(
            ErrorPhase::Topology,
            ErrorCode::TopologyChanged,
            u64::from(cpu),
        )
        .on_cpu(cpu_index));
    }
    if unsafe {
        (*vcpu).xsave_area.is_null()
            || ((*vcpu).xsave_area as usize) & 63 != 0
            || (*vcpu).xsave_size != (*vcpu).capabilities.xsave.maximum_size
    } {
        return Err(
            MonadError::new(ErrorPhase::Launch, ErrorCode::InvalidGuestState, 0).on_cpu(cpu_index),
        );
    }

    let original = match prepare_control_registers(unsafe { &(*vcpu).capabilities }) {
        Ok(original) => original,
        Err(error) => {
            return Err(error.on_cpu(cpu_index));
        }
    };
    unsafe { (*vcpu).original_controls = original };

    if let Err(error) = vmxon(unsafe { (*vcpu).vmxon_pa }, unsafe { (*vcpu).vmxon_permit }) {
        restore_control_registers(original);
        return Err(error.on_cpu(cpu_index));
    }

    let guest_desc = match unsafe { Descriptors::capture_current() } {
        Ok(descriptors) => descriptors,
        Err(error) => {
            unsafe { vmxoff_or_fatal(vcpu) };
            restore_control_registers(original);
            return Err(error.on_cpu(cpu_index));
        }
    };
    (*vcpu).guest_desc = guest_desc;
    // Per-CPU kernel descriptors are retained; root paging belongs to the system process.
    let host_desc = match unsafe { Descriptors::capture_current() } {
        Ok(descriptors) => descriptors,
        Err(error) => {
            unsafe { vmxoff_or_fatal(vcpu) };
            restore_control_registers(original);
            return Err(error.on_cpu(cpu_index));
        }
    };
    (*vcpu).host_desc = host_desc;

    unsafe { capture_registers(&mut (*vcpu).regs) };

    match unsafe { setup_vmcs(vcpu) } {
        Ok(()) => {}
        Err(error) => {
            unsafe { vmxoff_or_fatal(vcpu) };
            restore_control_registers(original);
            return Err(error.on_cpu(cpu_index));
        }
    }

    // hardware may touch vmx allocations until vmxoff.
    unsafe { (*vcpu).active.store(true, Ordering::Release) };
    if let Err(error) = unsafe { vmlaunch(&mut (*vcpu).regs) } {
        unsafe { vmxoff_or_fatal(vcpu) };
        unsafe { (*vcpu).active.store(false, Ordering::Release) };
        // Failed initial entry returned with the root mask; native caller owns the original.
        crate::arch::intel::state::restore_native_xcr0(unsafe { (*vcpu).guest_xcr0 });
        restore_control_registers(original);
        return Err(error.on_cpu(cpu_index));
    }
    if unsafe { (*vcpu).active.load(Ordering::Acquire) } {
        Ok(())
    } else {
        Err(
            MonadError::new(ErrorPhase::Launch, ErrorCode::LaunchRollbackFailure, 0)
                .on_cpu(cpu_index),
        )
    }
}
