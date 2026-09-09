extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;

use hypervisor::error::{ErrorCode, ErrorPhase, MonadError};
use wdk_sys::{
    ntddk::{
        IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink, IofCompleteRequest,
        KeGetCurrentIrql,
    },
    BOOLEAN, DEVICE_OBJECT, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DRIVER_OBJECT,
    FILE_DEVICE_SECURE_OPEN, GUID, IRP_MJ_CLEANUP, IRP_MJ_CLOSE, IRP_MJ_CREATE,
    IRP_MJ_DEVICE_CONTROL, NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, PDRIVER_OBJECT, PIRP,
    STATUS_SUCCESS, UNICODE_STRING,
};

use crate::ioctl::{
    self, ActivateViewRequest, AllocateBackingRequest, AllocateBackingResponse,
    ApplyEditBatchRequest, BackingIdWire, CpuSetWordWire, CreateDraftRequest, CreateDraftResponse,
    DevicePhysicalRangeWire, DiscardDraftRequest, EditWire, FreeBackingRequest, GetCapsResponse,
    GetVcpuStateRequest, GetVcpuStateResponse, ListViewsRequest, ListViewsResponse,
    PublishViewRequest, PublishViewResponse, QueryMappingRequest, QueryMappingResponse,
    ReadEventsRequest, ReadEventsResponse, ResponseHeader, StartVmmRequest, ViewIdWire,
    ViewRecordWire, ABI_VERSION, ALLOCATION_FLAG_IMMUTABLE, EDIT_MAP_BACKING_4K,
    EDIT_RESTORE_FROM_BASE, EDIT_SET_PERMISSIONS, IOCTL_ACTIVATE_VIEW, IOCTL_ALLOCATE_BACKING,
    IOCTL_APPLY_EDIT_BATCH, IOCTL_CREATE_DRAFT, IOCTL_DISCARD_DRAFT, IOCTL_FREE_BACKING,
    IOCTL_GET_CAPS, IOCTL_GET_VCPU_STATE, IOCTL_LIST_VIEWS, IOCTL_PUBLISH_VIEW,
    IOCTL_QUERY_MAPPING, IOCTL_READ_EVENTS, IOCTL_START_VMM, IOCTL_STOP_VMM, IOCTL_WRITE_BACKING,
    MAPPING_BACKING, MAPPING_IDENTITY, MAPPING_NOT_PRESENT, MAX_CPU_SET_WORDS, OBJECT_DRAFT_VIEW,
    OBJECT_PUBLISHED_VIEW, VIEW_STATE_PUBLISHED,
};
use crate::session::ControllerSession;

pub const DEVICE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
const DEVICE_NAME: &str = "\\Device\\MonadResearch";
const DOS_NAME: &str = "\\DosDevices\\MonadResearch";
const IO_NO_INCREMENT: i8 = 0;
const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS = 0xC000_0010u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000_009Au32 as i32;

static SESSION: ControllerSession = ControllerSession::new();

#[link(name = "wdmsec", kind = "static")]
unsafe extern "system" {
    fn WdmlibIoCreateDeviceSecure(
        driver_object: PDRIVER_OBJECT,
        device_extension_size: u32,
        device_name: *mut UNICODE_STRING,
        device_type: u32,
        device_characteristics: u32,
        exclusive: BOOLEAN,
        default_sddl: PCUNICODE_STRING,
        device_class_guid: *const GUID,
        device_object: *mut PDEVICE_OBJECT,
    ) -> NTSTATUS;
}

#[link(name = "cng")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut c_void,
        buffer: *mut u8,
        length: u32,
        flags: u32,
    ) -> NTSTATUS;
}

const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
const DEVICE_CLASS_GUID: GUID = GUID {
    Data1: 0xc450_91b8,
    Data2: 0xef41,
    Data3: 0x4f5f,
    Data4: [0x97, 0x60, 0x46, 0x97, 0xc5, 0x44, 0x13, 0x8e],
};

struct WideString {
    buffer: [u16; 64],
    length: u16,
}

impl WideString {
    fn from_ascii(value: &str) -> Result<Self, NTSTATUS> {
        if !value.is_ascii() || value.len() >= 64 {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        let mut buffer = [0u16; 64];
        for (destination, source) in buffer.iter_mut().zip(value.as_bytes()) {
            *destination = u16::from(*source);
        }
        Ok(Self {
            buffer,
            length: value.len() as u16,
        })
    }

    fn unicode(&mut self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: self.length * 2,
            MaximumLength: (self.length + 1) * 2,
            Buffer: self.buffer.as_mut_ptr(),
        }
    }
}

pub fn acl_allows(principal: &str) -> bool {
    DEVICE_SDDL == "D:P(A;;GA;;;SY)(A;;GA;;;BA)" && matches!(principal, "SY" | "BA")
}

/// creates monad's buffered control device.
///
/// # Safety
///
/// `driver` is the live object supplied to `DriverEntry`. this function runs
/// once at `PASSIVE_LEVEL` before any dispatch can arrive.
pub unsafe fn create(driver: &mut DRIVER_OBJECT) -> NTSTATUS {
    let mut device_name = match WideString::from_ascii(DEVICE_NAME) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut dos_name = match WideString::from_ascii(DOS_NAME) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut sddl = match WideString::from_ascii(DEVICE_SDDL) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut device_unicode = device_name.unicode();
    let mut dos_unicode = dos_name.unicode();
    let sddl_unicode = sddl.unicode();
    let mut device: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        WdmlibIoCreateDeviceSecure(
            driver,
            0,
            &mut device_unicode,
            ioctl::FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            1,
            &sddl_unicode,
            &DEVICE_CLASS_GUID,
            &mut device,
        )
    };
    if status < 0 {
        return status;
    }
    if device.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let link_status = unsafe { IoCreateSymbolicLink(&mut dos_unicode, &mut device_unicode) };
    if link_status < 0 {
        unsafe { IoDeleteDevice(device) };
        return link_status;
    }
    unsafe {
        (*device).Flags |= DO_BUFFERED_IO;
        (*device).Flags &= !DO_DEVICE_INITIALIZING;
    }
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);
    driver.MajorFunction[IRP_MJ_CLEANUP as usize] = Some(dispatch_cleanup);
    STATUS_SUCCESS
}

/// removes the symbolic link and device object.
///
/// # Safety
///
/// `driver` is live and monad has stopped accepting dispatches.
pub unsafe fn destroy(driver: *mut DRIVER_OBJECT) {
    let mut dos_name = match WideString::from_ascii(DOS_NAME) {
        Ok(value) => value,
        Err(_) => return,
    };
    let mut dos_unicode = dos_name.unicode();
    let _ = unsafe { IoDeleteSymbolicLink(&mut dos_unicode) };
    if !driver.is_null() {
        let device = unsafe { (*driver).DeviceObject };
        if !device.is_null() {
            unsafe { IoDeleteDevice(device) };
        }
    }
}

unsafe extern "C" fn dispatch_create(_device: *mut DEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let nonce = match secure_nonce() {
        Ok(value) => value,
        Err(status) => return unsafe { complete(irp, status, 0) },
    };
    let status = match SESSION.acquire(nonce) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => ioctl::ntstatus(error),
    };
    unsafe { complete(irp, status, 0) }
}

unsafe extern "C" fn dispatch_cleanup(_device: *mut DEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    // Windows owns outstanding I/O until IRP_MJ_CLOSE. Quiesce new admission now.
    let nonce = SESSION.active_nonce();
    if nonce != 0 {
        if let Err(error) = SESSION.begin_close(nonce) {
            return unsafe { complete(irp, ioctl::ntstatus(error), 0) };
        }
    }
    unsafe { complete(irp, STATUS_SUCCESS, 0) }
}

unsafe extern "C" fn dispatch_close(_device: *mut DEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let nonce = SESSION.active_nonce();
    if nonce != 0 {
        {
            let drain = SESSION.close_owner();
            // WDM close arrives only after outstanding I/O has completed/cancelled.
            // No spin, blocking dependency, or abandoned asynchronous owner.
            if !drain.is_drained() {
                unsafe {
                    wdk_sys::ntddk::KeBugCheckEx(0x4d4e4431, 12, 0, 0, 0);
                }
            }
            unsafe {
                hypervisor::vmm::shutdown_and_release();
            }
            if drain.finish().is_err() {
                unsafe {
                    wdk_sys::ntddk::KeBugCheckEx(0x4d4e4431, 12, 1, 0, 0);
                }
            }
        }
    }
    unsafe { complete(irp, STATUS_SUCCESS, 0) }
}

unsafe extern "C" fn dispatch_device_control(_device: *mut DEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    if irp.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if unsafe { KeGetCurrentIrql() } != 0 {
        return unsafe { complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0) };
    }
    let stack = unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    };
    if stack.is_null() {
        return unsafe { complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0) };
    }
    let parameters = unsafe { (*stack).Parameters.DeviceIoControl };
    let input_length = parameters.InputBufferLength as usize;
    let output_length = parameters.OutputBufferLength as usize;
    let code = parameters.IoControlCode;
    if input_length > ioctl::MAX_REQUEST_BYTES || output_length > ioctl::MAX_REQUEST_BYTES {
        return unsafe { complete(irp, 0xC000_000Du32 as i32, 0) };
    }
    let buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer.cast::<u8>() };
    if buffer.is_null() {
        return unsafe { complete(irp, 0xC000_0023u32 as i32, 0) };
    }
    let input = unsafe { core::slice::from_raw_parts(buffer.cast_const(), input_length) };
    let mut owned = Vec::new();
    if owned.try_reserve_exact(input_length).is_err() {
        return unsafe { complete(irp, STATUS_INSUFFICIENT_RESOURCES, 0) };
    }
    owned.extend_from_slice(input);
    let output = unsafe { core::slice::from_raw_parts_mut(buffer, output_length) };
    output.fill(0);
    let (status, information) = execute(code, &owned, output);
    unsafe { complete(irp, status, information) }
}

fn execute(code: u32, input: &[u8], output: &mut [u8]) -> (NTSTATUS, usize) {
    let validated = match ioctl::validate_request(code, input, output.len(), SESSION.active_nonce())
    {
        Ok(value) => value,
        Err(error) => return write_error(code, input, output, error),
    };
    let state = hypervisor::vmm::lifecycle_state();
    let _request = match ioctl::validate_and_begin(&SESSION, validated, state) {
        Ok(value) => value,
        Err(error) => return write_error(code, input, output, error),
    };
    let result = match code {
        IOCTL_GET_CAPS => execute_get_caps(validated.header, output),
        IOCTL_START_VMM => {
            let request = match ioctl::read_pod::<StartVmmRequest>(input, 0) {
                Ok(value) => value,
                Err(error) => return write_error(code, input, output, error),
            };
            if request.rendezvous_timeout_tsc == 0 {
                Err(MonadError::new(
                    ErrorPhase::Device,
                    ErrorCode::InvalidRange,
                    request.aperture_limit,
                ))
            } else {
                let device_ranges = match device_ranges_from_wire(input, request.device_range_count)
                {
                    Ok(value) => value,
                    Err(error) => return write_error(code, input, output, error),
                };
                unsafe {
                    hypervisor::vmm::vmm_init(hypervisor::vmm::VmmStartConfig {
                        session_nonce: SESSION.active_nonce(),
                        aperture_limit: request.aperture_limit,
                        rendezvous_timeout_tsc: request.rendezvous_timeout_tsc,
                        device_ranges,
                    })
                }
                .map(|()| size_of::<ResponseHeader>())
            }
        }
        IOCTL_STOP_VMM => {
            unsafe { hypervisor::vmm::vmm_shutdown() }.map(|()| size_of::<ResponseHeader>())
        }
        IOCTL_ALLOCATE_BACKING => execute_allocate_backing(validated.header, input, output),
        IOCTL_WRITE_BACKING => execute_write_backing(input).map(|()| size_of::<ResponseHeader>()),
        IOCTL_FREE_BACKING => execute_free_backing(input).map(|()| size_of::<ResponseHeader>()),
        IOCTL_CREATE_DRAFT => execute_create_draft(validated.header, input, output),
        IOCTL_APPLY_EDIT_BATCH => {
            execute_apply_edit_batch(input).map(|()| size_of::<ResponseHeader>())
        }
        IOCTL_DISCARD_DRAFT => execute_discard_draft(input).map(|()| size_of::<ResponseHeader>()),
        IOCTL_PUBLISH_VIEW => execute_publish_view(validated.header, input, output),
        IOCTL_QUERY_MAPPING => execute_query_mapping(validated.header, input, output),
        IOCTL_LIST_VIEWS => execute_list_views(validated.header, input, output),
        IOCTL_ACTIVATE_VIEW => execute_activate_view(input).map(|()| size_of::<ResponseHeader>()),
        IOCTL_READ_EVENTS => execute_read_events(validated.header, input, output),
        IOCTL_GET_VCPU_STATE => execute_get_vcpu_state(validated.header, input, output),
        _ => Err(MonadError::new(
            ErrorPhase::Device,
            ErrorCode::WrongObjectState,
            u64::from(code),
        )),
    };
    match result {
        Ok(size) => {
            let header =
                ResponseHeader::success::<ResponseHeader>(validated.header, SESSION.active_nonce());
            if !matches!(
                code,
                IOCTL_GET_CAPS
                    | IOCTL_ALLOCATE_BACKING
                    | IOCTL_CREATE_DRAFT
                    | IOCTL_PUBLISH_VIEW
                    | IOCTL_QUERY_MAPPING
                    | IOCTL_LIST_VIEWS
                    | IOCTL_READ_EVENTS
                    | IOCTL_GET_VCPU_STATE
            ) {
                let _ = ioctl::write_pod(output, &header);
            }
            (STATUS_SUCCESS, size)
        }
        Err(error) => write_error(code, input, output, error),
    }
}

fn device_ranges_from_wire(
    input: &[u8],
    count: u32,
) -> Result<Vec<hypervisor::ept::PhysicalRange>, MonadError> {
    let mut ranges = Vec::new();
    ranges.try_reserve_exact(count as usize).map_err(|_| {
        MonadError::new(
            ErrorPhase::Device,
            ErrorCode::AllocationFailure,
            u64::from(count),
        )
    })?;
    let base = size_of::<StartVmmRequest>();
    for index in 0..count as usize {
        let offset = base
            .checked_add(
                index
                    .checked_mul(size_of::<DevicePhysicalRangeWire>())
                    .ok_or_else(|| {
                        MonadError::new(
                            ErrorPhase::Device,
                            ErrorCode::AddressOverflow,
                            index as u64,
                        )
                    })?,
            )
            .ok_or_else(|| {
                MonadError::new(ErrorPhase::Device, ErrorCode::AddressOverflow, base as u64)
            })?;
        let range = ioctl::read_pod::<DevicePhysicalRangeWire>(input, offset)?;
        if range.length == 0 || range.start.checked_add(range.length).is_none() {
            return Err(MonadError::new(
                ErrorPhase::Device,
                ErrorCode::InvalidRange,
                index as u64,
            ));
        }
        ranges.push(hypervisor::ept::PhysicalRange {
            start: range.start,
            length: range.length,
            kind: hypervisor::ept::PhysicalRangeKind::Device,
        });
    }
    Ok(ranges)
}

fn backing_from_wire(value: BackingIdWire) -> hypervisor::ept::BackingId {
    hypervisor::ept::BackingId {
        slot: value.slot,
        generation: value.generation,
        session_nonce: value.session_nonce,
    }
}

fn backing_to_wire(value: hypervisor::ept::BackingId) -> BackingIdWire {
    BackingIdWire {
        slot: value.slot,
        reserved: 0,
        generation: value.generation,
        session_nonce: value.session_nonce,
    }
}

fn view_from_wire(value: ViewIdWire) -> hypervisor::ept::ViewId {
    hypervisor::ept::ViewId {
        slot: value.slot,
        reserved: value.reserved,
        generation: value.generation,
    }
}

fn view_to_wire(value: hypervisor::ept::ViewId) -> ViewIdWire {
    ViewIdWire {
        slot: value.slot,
        reserved: 0,
        reserved1: 0,
        generation: value.generation,
    }
}

fn draft_from_wire(value: ioctl::DraftIdWire) -> hypervisor::ept::DraftId {
    hypervisor::ept::DraftId {
        slot: value.slot,
        reserved: value.reserved,
        generation: value.generation,
        session_nonce: value.session_nonce,
    }
}

fn draft_to_wire(value: hypervisor::ept::DraftId) -> ioctl::DraftIdWire {
    ioctl::DraftIdWire {
        slot: value.slot,
        reserved: 0,
        reserved1: 0,
        generation: value.generation,
        session_nonce: value.session_nonce,
    }
}

fn execute_allocate_backing(
    header: ioctl::RequestHeader,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonadError> {
    let request = ioctl::read_pod::<AllocateBackingRequest>(input, 0)?;
    let immutable = request.allocation_flags & ALLOCATION_FLAG_IMMUTABLE != 0;
    let backing = unsafe { hypervisor::vmm::allocate_backing(request.page_count, immutable) }?;
    let response = AllocateBackingResponse {
        header: ResponseHeader::success::<AllocateBackingResponse>(header, SESSION.active_nonce()),
        backing: backing_to_wire(backing),
    };
    ioctl::write_pod(output, &response)
}

fn execute_write_backing(input: &[u8]) -> Result<(), MonadError> {
    let request = ioctl::read_pod::<ioctl::WriteBackingRequest>(input, 0)?;
    let offset = usize::try_from(request.offset).map_err(|_| {
        MonadError::new(
            ErrorPhase::DraftEdit,
            ErrorCode::AddressOverflow,
            request.offset,
        )
    })?;
    let data_start = size_of::<ioctl::WriteBackingRequest>();
    let data_end = data_start
        .checked_add(request.data_length as usize)
        .ok_or_else(|| {
            MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::AddressOverflow,
                u64::from(request.data_length),
            )
        })?;
    let data = input.get(data_start..data_end).ok_or_else(|| {
        MonadError::new(
            ErrorPhase::Device,
            ErrorCode::InvalidStructureSize,
            input.len() as u64,
        )
    })?;
    unsafe { hypervisor::vmm::write_backing(backing_from_wire(request.backing), offset, data) }
}

fn execute_free_backing(input: &[u8]) -> Result<(), MonadError> {
    let request = ioctl::read_pod::<FreeBackingRequest>(input, 0)?;
    unsafe { hypervisor::vmm::free_backing(backing_from_wire(request.backing)) }
}

fn execute_create_draft(
    header: ioctl::RequestHeader,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonadError> {
    let request = ioctl::read_pod::<CreateDraftRequest>(input, 0)?;
    let draft = unsafe { hypervisor::vmm::create_draft(view_from_wire(request.source)) }?;
    let response = CreateDraftResponse {
        header: ResponseHeader::success::<CreateDraftResponse>(header, SESSION.active_nonce()),
        draft: draft_to_wire(draft),
    };
    ioctl::write_pod(output, &response)
}

fn permissions_from_wire(value: u8) -> Result<hypervisor::ept::EptPermissions, MonadError> {
    if value & !7 != 0 {
        return Err(MonadError::new(
            ErrorPhase::DraftEdit,
            ErrorCode::UnsupportedPermissionCombination,
            u64::from(value),
        ));
    }
    hypervisor::ept::EptPermissions::new(value & 1 != 0, value & 2 != 0, value & 4 != 0, true)
}

fn edit_from_wire(
    value: EditWire,
    aperture_end: u64,
) -> Result<hypervisor::ept::DraftEdit, MonadError> {
    match value.kind {
        EDIT_SET_PERMISSIONS => {
            if value.backing != BackingIdWire::default()
                || value.backing_page != 0
                || value.memory_type != 0
            {
                return Err(MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::UnsupportedFlags,
                    u64::from(value.kind),
                ));
            }
            Ok(hypervisor::ept::DraftEdit::SetPermissions {
                range: hypervisor::ept::GpaRange::new(value.gpa, value.length, aperture_end)?,
                permissions: permissions_from_wire(value.permissions)?,
            })
        }
        EDIT_MAP_BACKING_4K => {
            if value.length != hypervisor::ept::PAGE_SIZE_4K {
                return Err(MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::InvalidRange,
                    value.length,
                ));
            }
            let memory_type = match value.memory_type {
                6 => hypervisor::ept::BackingMemoryType::WriteBack,
                other => {
                    return Err(MonadError::new(
                        ErrorPhase::DraftEdit,
                        ErrorCode::UnsupportedMtrrCombination,
                        u64::from(other),
                    ))
                }
            };
            Ok(hypervisor::ept::DraftEdit::MapBacking4K {
                gpa: hypervisor::ept::GuestPhysicalAddress::from_page_aligned(value.gpa)?,
                backing: hypervisor::ept::BackingPageReference {
                    backing_id: backing_from_wire(value.backing),
                    page_index: value.backing_page,
                },
                permissions: permissions_from_wire(value.permissions)?,
                memory_type,
            })
        }
        EDIT_RESTORE_FROM_BASE => {
            if value.backing != BackingIdWire::default()
                || value.backing_page != 0
                || value.permissions != 0
                || value.memory_type != 0
            {
                return Err(MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::UnsupportedFlags,
                    u64::from(value.kind),
                ));
            }
            Ok(hypervisor::ept::DraftEdit::RestoreFromBase {
                range: hypervisor::ept::GpaRange::new(value.gpa, value.length, aperture_end)?,
            })
        }
        other => Err(MonadError::new(
            ErrorPhase::DraftEdit,
            ErrorCode::WrongObjectState,
            u64::from(other),
        )),
    }
}

fn execute_apply_edit_batch(input: &[u8]) -> Result<(), MonadError> {
    let request = ioctl::read_pod::<ApplyEditBatchRequest>(input, 0)?;
    let count = request.edit_count as usize;
    if count == 0 || count > hypervisor::ept::MAX_BATCH_EDITS {
        return Err(MonadError::new(
            ErrorPhase::DraftEdit,
            ErrorCode::InvalidRange,
            count as u64,
        ));
    }
    let aperture_end = hypervisor::vmm::aperture_end()?;
    let mut edits = Vec::new();
    edits.try_reserve_exact(count).map_err(|_| {
        MonadError::new(
            ErrorPhase::DraftEdit,
            ErrorCode::AllocationFailure,
            count as u64,
        )
    })?;
    for index in 0..count {
        let offset = size_of::<ApplyEditBatchRequest>()
            .checked_add(index.checked_mul(size_of::<EditWire>()).ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::AddressOverflow,
                    index as u64,
                )
            })?)
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::DraftEdit,
                    ErrorCode::AddressOverflow,
                    index as u64,
                )
            })?;
        let edit = ioctl::read_pod::<EditWire>(input, offset)
            .and_then(|wire| edit_from_wire(wire, aperture_end))
            .map_err(|error| error.at_operation(index as u32))?;
        edits.push(edit);
    }
    unsafe { hypervisor::vmm::apply_edit_batch(draft_from_wire(request.draft), &edits) }
}

fn execute_discard_draft(input: &[u8]) -> Result<(), MonadError> {
    let request = ioctl::read_pod::<DiscardDraftRequest>(input, 0)?;
    unsafe { hypervisor::vmm::discard_draft(draft_from_wire(request.draft)) }
}

fn execute_publish_view(
    header: ioctl::RequestHeader,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonadError> {
    let request = ioctl::read_pod::<PublishViewRequest>(input, 0)?;
    let view = unsafe { hypervisor::vmm::publish_view(draft_from_wire(request.draft)) }?;
    let response = PublishViewResponse {
        header: ResponseHeader::success::<PublishViewResponse>(header, SESSION.active_nonce()),
        view: view_to_wire(view),
        reserved: 0,
        reserved1: 0,
    };
    ioctl::write_pod(output, &response)
}

fn permissions_to_wire(value: hypervisor::ept::EptPermissions) -> u8 {
    u8::from(value.read()) | (u8::from(value.write()) << 1) | (u8::from(value.execute()) << 2)
}

fn leaf_size_log2(value: hypervisor::ept::EptLeafSize) -> u8 {
    match value {
        hypervisor::ept::EptLeafSize::Size4K => 12,
        hypervisor::ept::EptLeafSize::Size2M => 21,
        hypervisor::ept::EptLeafSize::Size1G => 30,
    }
}

fn execute_query_mapping(
    header: ioctl::RequestHeader,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonadError> {
    let request = ioctl::read_pod::<QueryMappingRequest>(input, 0)?;
    let page_gpa = request.gpa & !(hypervisor::ept::PAGE_SIZE_4K - 1);
    let gpa = hypervisor::ept::GuestPhysicalAddress::from_page_aligned(page_gpa)?;
    let result = match request.object_kind {
        OBJECT_PUBLISHED_VIEW if request.draft == ioctl::DraftIdWire::default() => {
            unsafe { hypervisor::vmm::query_view(view_from_wire(request.view), gpa) }?
        }
        OBJECT_DRAFT_VIEW if request.view == ViewIdWire::default() => {
            unsafe { hypervisor::vmm::query_draft(draft_from_wire(request.draft), gpa) }?
        }
        other => {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::WrongObjectState,
                u64::from(other),
            ))
        }
    };
    let offset_in_page = request.gpa & (hypervisor::ept::PAGE_SIZE_4K - 1);
    let response = match result {
        hypervisor::ept::WalkResult::Mapping(mapping) => {
            let (source_kind, source_backing, page_offset) = match mapping.source {
                hypervisor::ept::MappingSource::Identity => {
                    (MAPPING_IDENTITY, BackingIdWire::default(), request.gpa)
                }
                hypervisor::ept::MappingSource::Backing(reference) => (
                    MAPPING_BACKING,
                    backing_to_wire(reference.backing_id),
                    u64::from(reference.page_index) * hypervisor::ept::PAGE_SIZE_4K
                        + offset_in_page,
                ),
            };
            QueryMappingResponse {
                header: ResponseHeader::success::<QueryMappingResponse>(
                    header,
                    SESSION.active_nonce(),
                ),
                mapped: 1,
                permissions: permissions_to_wire(mapping.permissions),
                memory_type: mapping.memory_type as u8,
                leaf_size_log2: leaf_size_log2(mapping.leaf_size),
                source_kind,
                source_backing,
                page_offset,
                reserved: [0; 2],
            }
        }
        hypervisor::ept::WalkResult::NotPresent { .. } => QueryMappingResponse {
            header: ResponseHeader::success::<QueryMappingResponse>(header, SESSION.active_nonce()),
            mapped: 0,
            permissions: 0,
            memory_type: 0,
            leaf_size_log2: 0,
            source_kind: MAPPING_NOT_PRESENT,
            source_backing: BackingIdWire::default(),
            page_offset: 0,
            reserved: [0; 2],
        },
        hypervisor::ept::WalkResult::Invalid(error) => {
            return Err(MonadError::new(
                ErrorPhase::DraftEdit,
                ErrorCode::EptVerificationFailure,
                error.detail,
            ))
        }
    };
    ioctl::write_pod(output, &response)
}

fn execute_list_views(
    header: ioctl::RequestHeader,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonadError> {
    let request = ioctl::read_pod::<ListViewsRequest>(input, 0)?;
    let mut states =
        [hypervisor::vmm::PublicViewState::default(); hypervisor::ept::MAX_PUBLISHED_VIEWS];
    let (_, total) = unsafe { hypervisor::vmm::list_views(&mut states) }?;
    let start = request.start_index as usize;
    if start > total {
        return Err(MonadError::new(
            ErrorPhase::Device,
            ErrorCode::InvalidRange,
            start as u64,
        ));
    }
    let count = (request.max_records as usize).min(total - start);
    let response = ListViewsResponse {
        header: ResponseHeader::success::<ListViewsResponse>(header, SESSION.active_nonce()),
        record_count: count as u32,
        total_count: total as u32,
    };
    let mut cursor = ioctl::write_pod(output, &response)?;
    for state in &states[start..start + count] {
        let metadata = state.metadata;
        let record = ViewRecordWire {
            id: view_to_wire(state.id),
            source: view_to_wire(metadata.source),
            state: VIEW_STATE_PUBLISHED,
            table_pages: metadata.table_pages,
            leaf_count: u64::from(metadata.leaf_1g)
                + u64::from(metadata.leaf_2m)
                + u64::from(metadata.leaf_4k),
            readable_pages: metadata.readable_pages,
            writable_pages: metadata.writable_pages,
            executable_pages: metadata.executable_pages,
            backing_ref_count: metadata.backing_pages,
            cpu_word_count: 4,
            active_cpu_set: state.active_cpu_set,
        };
        let size = ioctl::write_pod(&mut output[cursor..], &record)?;
        cursor = cursor.checked_add(size).ok_or_else(|| {
            MonadError::new(
                ErrorPhase::Device,
                ErrorCode::AddressOverflow,
                cursor as u64,
            )
        })?;
    }
    Ok(cursor)
}

fn execute_activate_view(input: &[u8]) -> Result<(), MonadError> {
    let request = ioctl::read_pod::<ActivateViewRequest>(input, 0)?;
    if request.cpu_word_count == 0 || request.cpu_word_count > MAX_CPU_SET_WORDS {
        return Err(MonadError::new(
            ErrorPhase::Topology,
            ErrorCode::InvalidCpuSet,
            u64::from(request.cpu_word_count),
        ));
    }
    let count = request.cpu_word_count as usize;
    let mut words = Vec::new();
    words.try_reserve_exact(count).map_err(|_| {
        MonadError::new(
            ErrorPhase::Topology,
            ErrorCode::AllocationFailure,
            count as u64,
        )
    })?;
    for index in 0..count {
        let offset = size_of::<ActivateViewRequest>()
            .checked_add(
                index
                    .checked_mul(size_of::<CpuSetWordWire>())
                    .ok_or_else(|| {
                        MonadError::new(
                            ErrorPhase::Topology,
                            ErrorCode::AddressOverflow,
                            index as u64,
                        )
                    })?,
            )
            .ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::Topology,
                    ErrorCode::AddressOverflow,
                    index as u64,
                )
            })?;
        let word = ioctl::read_pod::<CpuSetWordWire>(input, offset)?;
        words.push(hypervisor::topology::CpuSetWord {
            group: word.group,
            reserved: word.reserved,
            mask: word.mask,
        });
    }
    unsafe { hypervisor::vmm::activate_view(view_from_wire(request.view), &words) }
}

fn execute_read_events(
    header: ioctl::RequestHeader,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonadError> {
    let request = ioctl::read_pod::<ReadEventsRequest>(input, 0)?;
    let count = request.max_records as usize;
    let mut records = Vec::new();
    records.try_reserve_exact(count).map_err(|_| {
        MonadError::new(
            ErrorPhase::Telemetry,
            ErrorCode::AllocationFailure,
            count as u64,
        )
    })?;
    records.resize(count, hypervisor::telemetry::EventRecord::zeroed());
    let snapshot = hypervisor::vmm::read_events(
        request.cpu_dense_index,
        request.after_sequence,
        &mut records,
    )?;
    let response = ReadEventsResponse {
        header: ResponseHeader::success::<ReadEventsResponse>(header, SESSION.active_nonce()),
        record_count: snapshot.count as u32,
        reserved: 0,
        next_sequence: snapshot.next_sequence,
        dropped: snapshot.dropped,
    };
    let base = ioctl::write_pod(output, &response)?;
    let mut cursor = base;
    for record in &records[..snapshot.count] {
        for word in record.encode_words() {
            let end = cursor.checked_add(8).ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::Telemetry,
                    ErrorCode::AddressOverflow,
                    cursor as u64,
                )
            })?;
            let output_len = output.len();
            let destination = output.get_mut(cursor..end).ok_or_else(|| {
                MonadError::new(
                    ErrorPhase::Telemetry,
                    ErrorCode::InvalidStructureSize,
                    output_len as u64,
                )
            })?;
            destination.copy_from_slice(&word.to_le_bytes());
            cursor = end;
        }
    }
    Ok(cursor)
}

fn execute_get_vcpu_state(
    header: ioctl::RequestHeader,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, MonadError> {
    let request = ioctl::read_pod::<GetVcpuStateRequest>(input, 0)?;
    let state = hypervisor::vmm::vcpu_state(request.cpu_dense_index)?;
    let response = GetVcpuStateResponse {
        header: ResponseHeader::success::<GetVcpuStateResponse>(header, SESSION.active_nonce()),
        cpu_dense_index: state.cpu_dense_index,
        vmx_state: u8::from(state.active),
        reserved0: 0,
        reserved1: 0,
        active_view: ViewIdWire {
            slot: state.active_view.slot,
            reserved: 0,
            reserved1: 0,
            generation: state.active_view.generation,
        },
        last_epoch: state.last_epoch,
        last_fatal: state.last_fatal,
        last_mailbox: state.last_mailbox,
        event_sequence: state.event_sequence,
        reserved: [0; 2],
    };
    ioctl::write_pod(output, &response)
}

fn execute_get_caps(request: ioctl::RequestHeader, output: &mut [u8]) -> Result<usize, MonadError> {
    let capabilities = hypervisor::vmm::current_capabilities()?;
    let response = GetCapsResponse {
        header: ResponseHeader::success::<GetCapsResponse>(request, SESSION.active_nonce()),
        driver_version: u32::from(ABI_VERSION),
        lifecycle: hypervisor::vmm::lifecycle_state() as u32,
        capability_bits: capabilities.capability_bits,
        aperture_end: capabilities.aperture_end,
        physaddr_width: capabilities.max_physical_address_bits,
        vbs_or_hypervisor_present: u8::from(capabilities.hypervisor_present),
        session_available: u8::from(SESSION.active_nonce() != 0),
        reserved0: 0,
        cpu_count: capabilities.cpu_count,
        max_views: hypervisor::ept::MAX_PUBLISHED_VIEWS as u16,
        max_drafts: hypervisor::ept::MAX_DRAFT_VIEWS as u16,
        max_batch_edits: hypervisor::ept::MAX_BATCH_EDITS as u16,
        reserved1: 0,
        reserved2: 0,
        max_backing_pages: hypervisor::ept::MAX_BACKING_PAGES as u32,
        reserved3: 0,
        reserved: [0; 2],
    };
    ioctl::write_pod(output, &response)
}

fn write_error(code: u32, input: &[u8], output: &mut [u8], error: MonadError) -> (NTSTATUS, usize) {
    let request_id = if input.len() >= size_of::<ioctl::RequestHeader>() {
        ioctl::read_pod::<ioctl::RequestHeader>(input, 0)
            .map(|header| header.request_id)
            .unwrap_or(0)
    } else {
        0
    };
    let output_size = ioctl::operation(code)
        .map(|operation| operation.output_size)
        .unwrap_or(size_of::<ResponseHeader>());
    if output.len() >= size_of::<ResponseHeader>() {
        let header = ResponseHeader {
            struct_size: output_size as u16,
            ..ResponseHeader::failure::<ResponseHeader>(request_id, error)
        };
        if ioctl::write_pod(output, &header).is_ok() {
            return (ioctl::ntstatus(error), size_of::<ResponseHeader>());
        }
    }
    (ioctl::ntstatus(error), 0)
}

fn secure_nonce() -> Result<u64, NTSTATUS> {
    for _ in 0..4 {
        let mut nonce = 0u64;
        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                (&mut nonce as *mut u64).cast(),
                size_of::<u64>() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(status);
        }
        if nonce != 0 {
            return Ok(nonce);
        }
    }
    Err(STATUS_INSUFFICIENT_RESOURCES)
}

unsafe fn complete(irp: PIRP, status: NTSTATUS, information: usize) -> NTSTATUS {
    if !irp.is_null() {
        unsafe {
            (*irp).IoStatus.__bindgen_anon_1.Status = status;
            (*irp).IoStatus.Information = information as u64;
            IofCompleteRequest(irp, IO_NO_INCREMENT);
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_acl() {
        assert_eq!(DEVICE_SDDL, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert!(acl_allows("SY"));
        assert!(acl_allows("BA"));
        assert!(!acl_allows("BU"));
        assert!(!acl_allows("WD"));
    }

    #[test]
    fn typed_adapter_conversion() {
        let permissions = edit_from_wire(
            EditWire {
                kind: EDIT_SET_PERMISSIONS,
                gpa: 0x1000,
                length: 0x2000,
                permissions: 5,
                ..EditWire::default()
            },
            0x10_000,
        )
        .expect("permission edit");
        assert!(matches!(
            permissions,
            hypervisor::ept::DraftEdit::SetPermissions { .. }
        ));

        let backing = BackingIdWire {
            slot: 3,
            reserved: 0,
            generation: 7,
            session_nonce: 11,
        };
        let mapping = edit_from_wire(
            EditWire {
                kind: EDIT_MAP_BACKING_4K,
                gpa: 0x3000,
                length: hypervisor::ept::PAGE_SIZE_4K,
                backing,
                backing_page: 2,
                permissions: 3,
                memory_type: 6,
                ..EditWire::default()
            },
            0x10_000,
        )
        .expect("mapping edit");
        assert!(matches!(
            mapping,
            hypervisor::ept::DraftEdit::MapBacking4K { .. }
        ));
        assert!(edit_from_wire(
            EditWire {
                kind: EDIT_MAP_BACKING_4K,
                gpa: 0x3000,
                length: hypervisor::ept::PAGE_SIZE_4K,
                backing,
                permissions: 3,
                memory_type: 5,
                ..EditWire::default()
            },
            0x10_000,
        )
        .is_err());
    }

    #[test]
    fn device_inventory_adapter_rejects_malformed_ranges() {
        let header = StartVmmRequest {
            device_range_count: 1,
            ..StartVmmRequest::default()
        };
        let mut input =
            alloc::vec![0u8; size_of::<StartVmmRequest>() + size_of::<DevicePhysicalRangeWire>()];
        ioctl::write_pod(&mut input, &header).expect("header");
        ioctl::write_pod(
            &mut input[size_of::<StartVmmRequest>()..],
            &DevicePhysicalRangeWire {
                start: 0xfec0_0000,
                length: 0x1000,
                reserved: 0,
            },
        )
        .expect("range");
        let ranges = device_ranges_from_wire(&input, 1).expect("valid range");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].kind, hypervisor::ept::PhysicalRangeKind::Device);

        ioctl::write_pod(
            &mut input[size_of::<StartVmmRequest>()..],
            &DevicePhysicalRangeWire {
                start: u64::MAX,
                length: 2,
                reserved: 0,
            },
        )
        .expect("overflowing range");
        assert!(device_ranges_from_wire(&input, 1).is_err());
    }
}
