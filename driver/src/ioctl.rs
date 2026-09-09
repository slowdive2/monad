use core::mem::{align_of, size_of};

use hypervisor::error::{ErrorCode, ErrorPhase, MonadError, NO_CPU, NO_OPERATION};
use hypervisor::lifecycle::LifecycleState;

use crate::session::ControllerSession;

pub const ABI_VERSION: u16 = 2;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
pub const METHOD_BUFFERED: u32 = 0;
pub const FILE_READ_ACCESS: u32 = 1;
pub const FILE_WRITE_ACCESS: u32 = 2;
pub const KNOWN_REQUEST_FLAGS: u32 = 0;
pub const ALLOCATION_FLAG_IMMUTABLE: u32 = 1;
pub const KNOWN_ALLOCATION_FLAGS: u32 = ALLOCATION_FLAG_IMMUTABLE;
pub const EDIT_SET_PERMISSIONS: u32 = 1;
pub const EDIT_MAP_BACKING_4K: u32 = 2;
pub const EDIT_RESTORE_FROM_BASE: u32 = 3;
pub const OBJECT_PUBLISHED_VIEW: u32 = 1;
pub const OBJECT_DRAFT_VIEW: u32 = 2;
pub const MAPPING_NOT_PRESENT: u32 = 0;
pub const MAPPING_IDENTITY: u32 = 1;
pub const MAPPING_BACKING: u32 = 2;
pub const VIEW_STATE_PUBLISHED: u32 = 1;
pub const MAX_CPU_SET_WORDS: u32 = 4;

pub const fn ctl_code(function: u32, access: u32) -> u32 {
    (FILE_DEVICE_UNKNOWN << 16) | (access << 14) | (function << 2) | METHOD_BUFFERED
}

pub const IOCTL_GET_CAPS: u32 = ctl_code(0x800, FILE_READ_ACCESS);
pub const IOCTL_START_VMM: u32 = ctl_code(0x801, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_STOP_VMM: u32 = ctl_code(0x802, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_ALLOCATE_BACKING: u32 = ctl_code(0x810, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_WRITE_BACKING: u32 = ctl_code(0x811, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_FREE_BACKING: u32 = ctl_code(0x812, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_CREATE_DRAFT: u32 = ctl_code(0x820, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_APPLY_EDIT_BATCH: u32 = ctl_code(0x821, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_DISCARD_DRAFT: u32 = ctl_code(0x822, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_PUBLISH_VIEW: u32 = ctl_code(0x823, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_QUERY_MAPPING: u32 = ctl_code(0x824, FILE_READ_ACCESS);
pub const IOCTL_LIST_VIEWS: u32 = ctl_code(0x825, FILE_READ_ACCESS);
pub const IOCTL_ACTIVATE_VIEW: u32 = ctl_code(0x826, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
pub const IOCTL_READ_EVENTS: u32 = ctl_code(0x830, FILE_READ_ACCESS);
pub const IOCTL_GET_VCPU_STATE: u32 = ctl_code(0x831, FILE_READ_ACCESS);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestHeader {
    pub abi_version: u16,
    pub struct_size: u16,
    pub flags: u32,
    pub request_id: u64,
    pub session_nonce: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonadErrorWire {
    pub phase: u32,
    pub code: u32,
    pub cpu_dense_index: u16,
    pub reserved: u16,
    pub operation_index: u32,
    pub detail: u64,
}

impl MonadErrorWire {
    pub const fn ok() -> Self {
        Self {
            phase: 0,
            code: 0,
            cpu_dense_index: NO_CPU,
            reserved: 0,
            operation_index: NO_OPERATION,
            detail: 0,
        }
    }
}

impl From<MonadError> for MonadErrorWire {
    fn from(value: MonadError) -> Self {
        Self {
            phase: value.phase as u32,
            code: value.code as u32,
            cpu_dense_index: value.cpu_dense_index,
            reserved: 0,
            operation_index: value.operation_index,
            detail: value.detail,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResponseHeader {
    pub abi_version: u16,
    pub struct_size: u16,
    pub flags: u32,
    pub request_id: u64,
    pub session_nonce: u64,
    pub error: MonadErrorWire,
}

impl ResponseHeader {
    pub fn success<T>(request: RequestHeader, session_nonce: u64) -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: size_of::<T>() as u16,
            flags: 0,
            request_id: request.request_id,
            session_nonce,
            error: MonadErrorWire::ok(),
        }
    }

    pub fn failure<T>(request_id: u64, error: MonadError) -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: size_of::<T>() as u16,
            flags: 0,
            request_id,
            session_nonce: 0,
            error: error.into(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ViewIdWire {
    pub slot: u16,
    pub reserved: u16,
    pub reserved1: u32,
    pub generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DraftIdWire {
    pub slot: u16,
    pub reserved: u16,
    pub reserved1: u32,
    pub generation: u64,
    pub session_nonce: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackingIdWire {
    pub slot: u32,
    pub reserved: u32,
    pub generation: u64,
    pub session_nonce: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuSetWordWire {
    pub group: u16,
    pub reserved: u16,
    pub reserved1: u32,
    pub mask: u64,
}

macro_rules! header_only {
    ($request:ident, $response:ident) => {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $request {
            pub header: RequestHeader,
        }

        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $response {
            pub header: ResponseHeader,
        }
    };
}

macro_rules! response_only {
    ($response:ident) => {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $response {
            pub header: ResponseHeader,
        }
    };
}

header_only!(GetCapsRequest, EmptyResponse);
header_only!(StopVmmRequest, StopVmmResponse);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetCapsResponse {
    pub header: ResponseHeader,
    pub driver_version: u32,
    pub lifecycle: u32,
    pub capability_bits: u64,
    pub aperture_end: u64,
    pub physaddr_width: u8,
    pub vbs_or_hypervisor_present: u8,
    pub session_available: u8,
    pub reserved0: u8,
    pub cpu_count: u16,
    pub max_views: u16,
    pub max_drafts: u16,
    pub max_batch_edits: u16,
    pub reserved1: u16,
    pub reserved2: u16,
    pub max_backing_pages: u32,
    pub reserved3: u32,
    pub reserved: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartVmmRequest {
    pub header: RequestHeader,
    pub aperture_limit: u64,
    pub rendezvous_timeout_tsc: u64,
    pub device_range_count: u32,
    pub reserved0: u32,
    pub reserved1: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DevicePhysicalRangeWire {
    pub start: u64,
    pub length: u64,
    pub reserved: u64,
}

response_only!(StartVmmResponse);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocateBackingRequest {
    pub header: RequestHeader,
    pub page_count: u32,
    pub allocation_flags: u32,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocateBackingResponse {
    pub header: ResponseHeader,
    pub backing: BackingIdWire,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteBackingRequest {
    pub header: RequestHeader,
    pub backing: BackingIdWire,
    pub offset: u64,
    pub data_length: u32,
    pub reserved: u32,
}

response_only!(WriteBackingResponse);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FreeBackingRequest {
    pub header: RequestHeader,
    pub backing: BackingIdWire,
}

response_only!(FreeBackingResponse);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateDraftRequest {
    pub header: RequestHeader,
    pub source: ViewIdWire,
    pub reserved: u32,
    pub reserved1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateDraftResponse {
    pub header: ResponseHeader,
    pub draft: DraftIdWire,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EditWire {
    pub kind: u32,
    pub flags: u32,
    pub gpa: u64,
    pub length: u64,
    pub backing: BackingIdWire,
    pub backing_page: u32,
    pub permissions: u8,
    pub memory_type: u8,
    pub reserved0: u16,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyEditBatchRequest {
    pub header: RequestHeader,
    pub draft: DraftIdWire,
    pub edit_count: u32,
    pub reserved: u32,
}

response_only!(ApplyEditBatchResponse);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiscardDraftRequest {
    pub header: RequestHeader,
    pub draft: DraftIdWire,
}

response_only!(DiscardDraftResponse);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublishViewRequest {
    pub header: RequestHeader,
    pub draft: DraftIdWire,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublishViewResponse {
    pub header: ResponseHeader,
    pub view: ViewIdWire,
    pub reserved: u32,
    pub reserved1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryMappingRequest {
    pub header: RequestHeader,
    pub object_kind: u32,
    pub reserved0: u32,
    pub view: ViewIdWire,
    pub draft: DraftIdWire,
    pub gpa: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryMappingResponse {
    pub header: ResponseHeader,
    pub mapped: u8,
    pub permissions: u8,
    pub memory_type: u8,
    pub leaf_size_log2: u8,
    pub source_kind: u32,
    pub source_backing: BackingIdWire,
    pub page_offset: u64,
    pub reserved: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListViewsRequest {
    pub header: RequestHeader,
    pub start_index: u32,
    pub max_records: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ViewRecordWire {
    pub id: ViewIdWire,
    pub source: ViewIdWire,
    pub state: u32,
    pub table_pages: u32,
    pub leaf_count: u64,
    pub readable_pages: u64,
    pub writable_pages: u64,
    pub executable_pages: u64,
    pub backing_ref_count: u32,
    pub cpu_word_count: u32,
    pub active_cpu_set: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListViewsResponse {
    pub header: ResponseHeader,
    pub record_count: u32,
    pub total_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivateViewRequest {
    pub header: RequestHeader,
    pub view: ViewIdWire,
    pub cpu_word_count: u32,
    pub reserved: u32,
}

response_only!(ActivateViewResponse);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadEventsRequest {
    pub header: RequestHeader,
    pub cpu_dense_index: u16,
    pub reserved0: u16,
    pub max_records: u32,
    pub after_sequence: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadEventsResponse {
    pub header: ResponseHeader,
    pub record_count: u32,
    pub reserved: u32,
    pub next_sequence: u64,
    pub dropped: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetVcpuStateRequest {
    pub header: RequestHeader,
    pub cpu_dense_index: u16,
    pub reserved0: u16,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetVcpuStateResponse {
    pub header: ResponseHeader,
    pub cpu_dense_index: u16,
    pub vmx_state: u8,
    pub reserved0: u8,
    pub reserved1: u32,
    pub active_view: ViewIdWire,
    pub last_epoch: u64,
    pub last_fatal: u32,
    pub last_mailbox: u32,
    pub event_sequence: u64,
    pub reserved: [u64; 2],
}

const _: [(); 24] = [(); size_of::<RequestHeader>()];
const _: [(); 8] = [(); align_of::<RequestHeader>()];
const _: [(); 48] = [(); size_of::<ResponseHeader>()];
const _: [(); 8] = [(); align_of::<ResponseHeader>()];
const _: [(); 24] = [(); size_of::<MonadErrorWire>()];
const _: [(); 8] = [(); align_of::<MonadErrorWire>()];

macro_rules! abi_layout {
    ($type:ty, $size:expr) => {
        const _: [(); $size] = [(); size_of::<$type>()];
        const _: [(); 8] = [(); align_of::<$type>()];
    };
}

abi_layout!(ViewIdWire, 16);
abi_layout!(DraftIdWire, 24);
abi_layout!(BackingIdWire, 24);
abi_layout!(CpuSetWordWire, 16);
abi_layout!(GetCapsRequest, 24);
abi_layout!(EmptyResponse, 48);
abi_layout!(GetCapsResponse, 112);
abi_layout!(StartVmmRequest, 56);
abi_layout!(DevicePhysicalRangeWire, 24);
abi_layout!(StartVmmResponse, 48);
abi_layout!(StopVmmRequest, 24);
abi_layout!(StopVmmResponse, 48);
abi_layout!(AllocateBackingRequest, 40);
abi_layout!(AllocateBackingResponse, 72);
abi_layout!(WriteBackingRequest, 64);
abi_layout!(WriteBackingResponse, 48);
abi_layout!(FreeBackingRequest, 48);
abi_layout!(FreeBackingResponse, 48);
abi_layout!(CreateDraftRequest, 48);
abi_layout!(CreateDraftResponse, 72);
abi_layout!(EditWire, 64);
abi_layout!(ApplyEditBatchRequest, 56);
abi_layout!(ApplyEditBatchResponse, 48);
abi_layout!(DiscardDraftRequest, 48);
abi_layout!(DiscardDraftResponse, 48);
abi_layout!(PublishViewRequest, 48);
abi_layout!(PublishViewResponse, 72);
abi_layout!(QueryMappingRequest, 80);
abi_layout!(QueryMappingResponse, 104);
abi_layout!(ListViewsRequest, 32);
abi_layout!(ViewRecordWire, 112);
abi_layout!(ListViewsResponse, 56);
abi_layout!(ActivateViewRequest, 48);
abi_layout!(ActivateViewResponse, 48);
abi_layout!(ReadEventsRequest, 40);
abi_layout!(ReadEventsResponse, 72);
abi_layout!(GetVcpuStateRequest, 32);
abi_layout!(GetVcpuStateResponse, 112);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationDescriptor {
    pub code: u32,
    pub input_size: usize,
    pub output_size: usize,
    pub mutable: bool,
    pub zero_nonce: bool,
    pub trailing_count_offset: Option<usize>,
    pub trailing_element_size: usize,
}

pub const OPERATIONS: [OperationDescriptor; 15] = [
    op::<GetCapsRequest, GetCapsResponse>(IOCTL_GET_CAPS, false, true, None, 0),
    op::<StartVmmRequest, StartVmmResponse>(
        IOCTL_START_VMM,
        true,
        false,
        Some(core::mem::offset_of!(StartVmmRequest, device_range_count)),
        size_of::<DevicePhysicalRangeWire>(),
    ),
    op::<StopVmmRequest, StopVmmResponse>(IOCTL_STOP_VMM, true, false, None, 0),
    op::<AllocateBackingRequest, AllocateBackingResponse>(
        IOCTL_ALLOCATE_BACKING,
        true,
        false,
        None,
        0,
    ),
    op::<WriteBackingRequest, WriteBackingResponse>(
        IOCTL_WRITE_BACKING,
        true,
        false,
        Some(core::mem::offset_of!(WriteBackingRequest, data_length)),
        1,
    ),
    op::<FreeBackingRequest, FreeBackingResponse>(IOCTL_FREE_BACKING, true, false, None, 0),
    op::<CreateDraftRequest, CreateDraftResponse>(IOCTL_CREATE_DRAFT, true, false, None, 0),
    op::<ApplyEditBatchRequest, ApplyEditBatchResponse>(
        IOCTL_APPLY_EDIT_BATCH,
        true,
        false,
        Some(core::mem::offset_of!(ApplyEditBatchRequest, edit_count)),
        size_of::<EditWire>(),
    ),
    op::<DiscardDraftRequest, DiscardDraftResponse>(IOCTL_DISCARD_DRAFT, true, false, None, 0),
    op::<PublishViewRequest, PublishViewResponse>(IOCTL_PUBLISH_VIEW, true, false, None, 0),
    op::<QueryMappingRequest, QueryMappingResponse>(IOCTL_QUERY_MAPPING, false, false, None, 0),
    op::<ListViewsRequest, ListViewsResponse>(IOCTL_LIST_VIEWS, false, false, None, 0),
    op::<ActivateViewRequest, ActivateViewResponse>(
        IOCTL_ACTIVATE_VIEW,
        true,
        false,
        Some(core::mem::offset_of!(ActivateViewRequest, cpu_word_count)),
        size_of::<CpuSetWordWire>(),
    ),
    op::<ReadEventsRequest, ReadEventsResponse>(IOCTL_READ_EVENTS, false, false, None, 0),
    op::<GetVcpuStateRequest, GetVcpuStateResponse>(IOCTL_GET_VCPU_STATE, false, false, None, 0),
];

const fn op<I, O>(
    code: u32,
    mutable: bool,
    zero_nonce: bool,
    trailing_count_offset: Option<usize>,
    trailing_element_size: usize,
) -> OperationDescriptor {
    OperationDescriptor {
        code,
        input_size: size_of::<I>(),
        output_size: size_of::<O>(),
        mutable,
        zero_nonce,
        trailing_count_offset,
        trailing_element_size,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedRequest {
    pub descriptor: OperationDescriptor,
    pub header: RequestHeader,
    pub total_input_size: usize,
}

pub fn operation(code: u32) -> Result<OperationDescriptor, MonadError> {
    OPERATIONS
        .iter()
        .copied()
        .find(|entry| entry.code == code)
        .ok_or_else(|| device_error(ErrorCode::WrongObjectState, u64::from(code)))
}

pub fn validate_request(
    code: u32,
    input: &[u8],
    output_len: usize,
    active_nonce: u64,
) -> Result<ValidatedRequest, MonadError> {
    let descriptor = operation(code)?;
    if input.len() > MAX_REQUEST_BYTES {
        return Err(device_error(ErrorCode::InvalidRange, input.len() as u64));
    }
    if output_len > MAX_REQUEST_BYTES {
        return Err(device_error(ErrorCode::InvalidRange, output_len as u64));
    }
    if input.len() < size_of::<RequestHeader>() {
        return Err(device_error(
            ErrorCode::InvalidStructureSize,
            input.len() as u64,
        ));
    }
    let header = read_pod::<RequestHeader>(input, 0)?;
    if header.abi_version != ABI_VERSION {
        return Err(device_error(
            ErrorCode::InvalidAbiVersion,
            u64::from(header.abi_version),
        ));
    }
    if usize::from(header.struct_size) != descriptor.input_size {
        return Err(device_error(
            ErrorCode::InvalidStructureSize,
            u64::from(header.struct_size),
        ));
    }
    if header.flags & !KNOWN_REQUEST_FLAGS != 0 {
        return Err(device_error(
            ErrorCode::UnsupportedFlags,
            u64::from(header.flags),
        ));
    }
    if output_len < descriptor.output_size {
        return Err(device_error(
            ErrorCode::InvalidStructureSize,
            output_len as u64,
        ));
    }
    let trailing_count = match descriptor.trailing_count_offset {
        Some(offset) => read_pod::<u32>(input, offset)? as usize,
        None => 0,
    };
    let trailing_size = trailing_count
        .checked_mul(descriptor.trailing_element_size)
        .ok_or_else(|| device_error(ErrorCode::AddressOverflow, trailing_count as u64))?;
    let total_input_size = descriptor
        .input_size
        .checked_add(trailing_size)
        .ok_or_else(|| device_error(ErrorCode::AddressOverflow, descriptor.input_size as u64))?;
    if total_input_size != input.len() || total_input_size > MAX_REQUEST_BYTES {
        return Err(device_error(
            ErrorCode::InvalidStructureSize,
            input.len() as u64,
        ));
    }
    let variable_output = match code {
        IOCTL_LIST_VIEWS => {
            let count = read_pod::<ListViewsRequest>(input, 0)?.max_records as usize;
            checked_variable_size(
                size_of::<ListViewsResponse>(),
                count,
                size_of::<ViewRecordWire>(),
            )?
        }
        IOCTL_READ_EVENTS => {
            let count = read_pod::<ReadEventsRequest>(input, 0)?.max_records as usize;
            checked_variable_size(
                size_of::<ReadEventsResponse>(),
                count,
                hypervisor::telemetry::EVENT_RECORD_BYTES,
            )?
        }
        _ => descriptor.output_size,
    };
    if variable_output > output_len || variable_output > MAX_REQUEST_BYTES {
        return Err(device_error(
            ErrorCode::InvalidStructureSize,
            variable_output as u64,
        ));
    }
    if descriptor.zero_nonce {
        if header.session_nonce != 0 && header.session_nonce != active_nonce {
            return Err(session_error(ErrorCode::WrongSession, header.session_nonce));
        }
    } else if header.session_nonce == 0 || header.session_nonce != active_nonce {
        return Err(session_error(ErrorCode::WrongSession, header.session_nonce));
    }
    validate_reserved(code, input)?;
    Ok(ValidatedRequest {
        descriptor,
        header,
        total_input_size,
    })
}

fn checked_variable_size(base: usize, count: usize, element: usize) -> Result<usize, MonadError> {
    if count == 0 {
        return Err(device_error(ErrorCode::InvalidRange, 0));
    }
    count
        .checked_mul(element)
        .and_then(|bytes| base.checked_add(bytes))
        .ok_or_else(|| device_error(ErrorCode::AddressOverflow, count as u64))
}

fn validate_reserved(code: u32, input: &[u8]) -> Result<(), MonadError> {
    let nonzero = match code {
        IOCTL_START_VMM => {
            let value = read_pod::<StartVmmRequest>(input, 0)?;
            value.reserved0 != 0
                || value.reserved1 != 0
                || device_ranges_have_reserved(input, value.device_range_count)?
        }
        IOCTL_ALLOCATE_BACKING => {
            let value = read_pod::<AllocateBackingRequest>(input, 0)?;
            value.reserved != 0 || value.allocation_flags & !KNOWN_ALLOCATION_FLAGS != 0
        }
        IOCTL_WRITE_BACKING => {
            let value = read_pod::<WriteBackingRequest>(input, 0)?;
            value.backing.reserved != 0 || value.reserved != 0
        }
        IOCTL_FREE_BACKING => read_pod::<FreeBackingRequest>(input, 0)?.backing.reserved != 0,
        IOCTL_CREATE_DRAFT => {
            let value = read_pod::<CreateDraftRequest>(input, 0)?;
            value.source.reserved != 0
                || value.source.reserved1 != 0
                || value.reserved != 0
                || value.reserved1 != 0
        }
        IOCTL_APPLY_EDIT_BATCH => {
            let value = read_pod::<ApplyEditBatchRequest>(input, 0)?;
            value.draft.reserved != 0
                || value.draft.reserved1 != 0
                || value.reserved != 0
                || edits_have_reserved(input, value.edit_count)?
        }
        IOCTL_DISCARD_DRAFT => {
            let value = read_pod::<DiscardDraftRequest>(input, 0)?;
            value.draft.reserved != 0 || value.draft.reserved1 != 0
        }
        IOCTL_PUBLISH_VIEW => {
            let value = read_pod::<PublishViewRequest>(input, 0)?;
            value.draft.reserved != 0 || value.draft.reserved1 != 0
        }
        IOCTL_QUERY_MAPPING => {
            let value = read_pod::<QueryMappingRequest>(input, 0)?;
            value.reserved0 != 0
                || value.view.reserved != 0
                || value.view.reserved1 != 0
                || value.draft.reserved != 0
                || value.draft.reserved1 != 0
        }
        IOCTL_ACTIVATE_VIEW => {
            let value = read_pod::<ActivateViewRequest>(input, 0)?;
            value.view.reserved != 0
                || value.view.reserved1 != 0
                || value.reserved != 0
                || cpu_words_have_reserved(input, value.cpu_word_count)?
        }
        IOCTL_READ_EVENTS => read_pod::<ReadEventsRequest>(input, 0)?.reserved0 != 0,
        IOCTL_GET_VCPU_STATE => {
            let value = read_pod::<GetVcpuStateRequest>(input, 0)?;
            value.reserved0 != 0 || value.reserved != 0
        }
        _ => false,
    };
    if nonzero {
        return Err(device_error(ErrorCode::UnsupportedFlags, 0));
    }
    Ok(())
}

fn edits_have_reserved(input: &[u8], count: u32) -> Result<bool, MonadError> {
    let base = size_of::<ApplyEditBatchRequest>();
    for index in 0..count as usize {
        let offset = base
            .checked_add(
                index
                    .checked_mul(size_of::<EditWire>())
                    .ok_or_else(|| device_error(ErrorCode::AddressOverflow, index as u64))?,
            )
            .ok_or_else(|| device_error(ErrorCode::AddressOverflow, base as u64))?;
        let edit = read_pod::<EditWire>(input, offset)?;
        if edit.flags != 0
            || edit.backing.reserved != 0
            || edit.reserved0 != 0
            || edit.reserved != 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn device_ranges_have_reserved(input: &[u8], count: u32) -> Result<bool, MonadError> {
    let base = size_of::<StartVmmRequest>();
    for index in 0..count as usize {
        let offset = base
            .checked_add(
                index
                    .checked_mul(size_of::<DevicePhysicalRangeWire>())
                    .ok_or_else(|| device_error(ErrorCode::AddressOverflow, index as u64))?,
            )
            .ok_or_else(|| device_error(ErrorCode::AddressOverflow, base as u64))?;
        if read_pod::<DevicePhysicalRangeWire>(input, offset)?.reserved != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn cpu_words_have_reserved(input: &[u8], count: u32) -> Result<bool, MonadError> {
    let base = size_of::<ActivateViewRequest>();
    for index in 0..count as usize {
        let offset = base
            .checked_add(
                index
                    .checked_mul(size_of::<CpuSetWordWire>())
                    .ok_or_else(|| device_error(ErrorCode::AddressOverflow, index as u64))?,
            )
            .ok_or_else(|| device_error(ErrorCode::AddressOverflow, base as u64))?;
        let word = read_pod::<CpuSetWordWire>(input, offset)?;
        if word.reserved != 0 || word.reserved1 != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn read_pod<T: Copy>(input: &[u8], offset: usize) -> Result<T, MonadError> {
    let end = offset
        .checked_add(size_of::<T>())
        .ok_or_else(|| device_error(ErrorCode::AddressOverflow, offset as u64))?;
    let bytes = input
        .get(offset..end)
        .ok_or_else(|| device_error(ErrorCode::InvalidStructureSize, input.len() as u64))?;
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), value.as_mut_ptr().cast(), bytes.len());
        Ok(value.assume_init())
    }
}

pub fn write_pod<T: Copy>(output: &mut [u8], value: &T) -> Result<usize, MonadError> {
    let size = size_of::<T>();
    let output_len = output.len();
    let destination = output
        .get_mut(..size)
        .ok_or_else(|| device_error(ErrorCode::InvalidStructureSize, output_len as u64))?;
    destination.fill(0);
    unsafe {
        core::ptr::copy_nonoverlapping((value as *const T).cast(), destination.as_mut_ptr(), size);
    }
    Ok(size)
}

pub fn lifecycle_allows(code: u32, state: LifecycleState) -> bool {
    match code {
        IOCTL_GET_CAPS => true,
        IOCTL_START_VMM => state == LifecycleState::Absent,
        IOCTL_STOP_VMM => state == LifecycleState::Running,
        IOCTL_ALLOCATE_BACKING
        | IOCTL_WRITE_BACKING
        | IOCTL_FREE_BACKING
        | IOCTL_CREATE_DRAFT
        | IOCTL_APPLY_EDIT_BATCH
        | IOCTL_DISCARD_DRAFT
        | IOCTL_PUBLISH_VIEW => state == LifecycleState::Running,
        IOCTL_READ_EVENTS | IOCTL_GET_VCPU_STATE => {
            matches!(state, LifecycleState::Running | LifecycleState::Absent)
        }
        IOCTL_QUERY_MAPPING | IOCTL_LIST_VIEWS => state == LifecycleState::Running,
        IOCTL_ACTIVATE_VIEW => state == LifecycleState::Running,
        _ => false,
    }
}

pub fn validate_and_begin<'a>(
    session: &'a ControllerSession,
    request: ValidatedRequest,
    state: LifecycleState,
) -> Result<Option<crate::session::SessionRequest<'a>>, MonadError> {
    if !lifecycle_allows(request.descriptor.code, state) {
        return Err(session_error(
            ErrorCode::InvalidLifecycleState,
            state as u64,
        ));
    }
    if request.descriptor.zero_nonce && request.header.session_nonce == 0 {
        return session.begin(session.active_nonce(), true).map(Some);
    }
    session.begin(request.header.session_nonce, true).map(Some)
}

pub fn ntstatus(error: MonadError) -> i32 {
    match error.code {
        ErrorCode::AccessDenied | ErrorCode::WrongSession => 0xC000_0022u32 as i32,
        ErrorCode::ControllerBusy | ErrorCode::RendezvousBusy => 0xC000_009Eu32 as i32,
        ErrorCode::InvalidAbiVersion => 0xC000_0059u32 as i32,
        ErrorCode::InvalidStructureSize => 0xC000_0023u32 as i32,
        ErrorCode::AllocationFailure | ErrorCode::EptAllocationFailure => 0xC000_009Au32 as i32,
        ErrorCode::InvalidLifecycleState | ErrorCode::WrongObjectState => 0xC000_0184u32 as i32,
        _ => 0xC000_000Du32 as i32,
    }
}

fn device_error(code: ErrorCode, detail: u64) -> MonadError {
    MonadError::new(ErrorPhase::Device, code, detail)
}

fn session_error(code: ErrorCode, detail: u64) -> MonadError {
    MonadError::new(ErrorPhase::Session, code, detail)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use core::mem::{align_of, offset_of, size_of};

    use super::*;

    fn bytes<T: Copy>(value: &T) -> alloc::vec::Vec<u8> {
        let mut output = vec![0u8; size_of::<T>()];
        unsafe {
            core::ptr::copy_nonoverlapping(
                (value as *const T).cast(),
                output.as_mut_ptr(),
                output.len(),
            );
        }
        output
    }

    fn request_header(size: usize, nonce: u64) -> RequestHeader {
        RequestHeader {
            abi_version: ABI_VERSION,
            struct_size: size as u16,
            flags: 0,
            request_id: 9,
            session_nonce: nonce,
        }
    }

    #[test]
    fn abi_layout() {
        assert_eq!(size_of::<RequestHeader>(), 24);
        assert_eq!(align_of::<RequestHeader>(), 8);
        assert_eq!(offset_of!(RequestHeader, session_nonce), 16);
        assert_eq!(size_of::<ResponseHeader>(), 48);
        assert_eq!(size_of::<MonadErrorWire>(), 24);
        assert_eq!(size_of::<ViewIdWire>(), 16);
        assert_eq!(size_of::<DraftIdWire>(), 24);
        assert_eq!(size_of::<BackingIdWire>(), 24);
        assert_eq!(size_of::<CpuSetWordWire>(), 16);
        assert_eq!(offset_of!(CpuSetWordWire, mask), 8);
        assert_eq!(size_of::<StartVmmRequest>(), 56);
        assert_eq!(offset_of!(StartVmmRequest, device_range_count), 40);
        assert_eq!(size_of::<DevicePhysicalRangeWire>(), 24);
        assert_eq!(size_of::<GetCapsResponse>(), 112);
        assert_eq!(offset_of!(GetCapsResponse, max_backing_pages), 88);
        assert_eq!(size_of::<EditWire>(), 64);
        assert_eq!(offset_of!(EditWire, reserved), 56);
        assert_eq!(size_of::<QueryMappingResponse>(), 104);
        assert_eq!(offset_of!(QueryMappingResponse, source_backing), 56);
        assert_eq!(size_of::<ViewRecordWire>(), 112);
        assert_eq!(offset_of!(ViewRecordWire, active_cpu_set), 80);
        assert_eq!(OPERATIONS.len(), 15);
        assert_eq!(IOCTL_GET_CAPS, ctl_code(0x800, FILE_READ_ACCESS));
        assert_eq!(IOCTL_START_VMM, ctl_code(0x801, 3));
        assert_eq!(IOCTL_STOP_VMM, ctl_code(0x802, 3));
        assert_eq!(IOCTL_ALLOCATE_BACKING, ctl_code(0x810, 3));
        assert_eq!(IOCTL_WRITE_BACKING, ctl_code(0x811, 3));
        assert_eq!(IOCTL_FREE_BACKING, ctl_code(0x812, 3));
        assert_eq!(IOCTL_CREATE_DRAFT, ctl_code(0x820, 3));
        assert_eq!(IOCTL_APPLY_EDIT_BATCH, ctl_code(0x821, 3));
        assert_eq!(IOCTL_DISCARD_DRAFT, ctl_code(0x822, 3));
        assert_eq!(IOCTL_PUBLISH_VIEW, ctl_code(0x823, 3));
        assert_eq!(IOCTL_QUERY_MAPPING, ctl_code(0x824, FILE_READ_ACCESS));
        assert_eq!(IOCTL_LIST_VIEWS, ctl_code(0x825, FILE_READ_ACCESS));
        assert_eq!(IOCTL_ACTIVATE_VIEW, ctl_code(0x826, 3));
        assert_eq!(IOCTL_READ_EVENTS, ctl_code(0x830, FILE_READ_ACCESS));
        assert_eq!(IOCTL_GET_VCPU_STATE, ctl_code(0x831, FILE_READ_ACCESS));
        for operation in OPERATIONS {
            assert_eq!(operation.code & 3, METHOD_BUFFERED);
            assert!(operation.input_size >= size_of::<RequestHeader>());
            assert!(operation.output_size >= size_of::<ResponseHeader>());
            assert_ne!((operation.code >> 2) & 0xfff, 0);
            assert_ne!((operation.code >> 14) & 3, 0);
        }
    }

    #[test]
    fn header_validation_matrix() {
        let request = GetCapsRequest {
            header: request_header(size_of::<GetCapsRequest>(), 0),
        };
        let valid = bytes(&request);
        for end in 0..valid.len() {
            assert!(validate_request(
                IOCTL_GET_CAPS,
                &valid[..end],
                size_of::<GetCapsResponse>(),
                7
            )
            .is_err());
        }
        validate_request(IOCTL_GET_CAPS, &valid, size_of::<GetCapsResponse>(), 7).expect("valid");
        assert!(
            validate_request(IOCTL_GET_CAPS, &valid, size_of::<GetCapsResponse>() - 1, 7).is_err()
        );
        let mut bad = request;
        bad.header.abi_version = ABI_VERSION - 1;
        assert_eq!(
            validate_request(
                IOCTL_GET_CAPS,
                &bytes(&bad),
                size_of::<GetCapsResponse>(),
                7
            )
            .expect_err("version")
            .code,
            ErrorCode::InvalidAbiVersion
        );
        bad = request;
        bad.header.flags = 1;
        assert_eq!(
            validate_request(
                IOCTL_GET_CAPS,
                &bytes(&bad),
                size_of::<GetCapsResponse>(),
                7
            )
            .expect_err("flags")
            .code,
            ErrorCode::UnsupportedFlags
        );
        bad = request;
        bad.header.struct_size -= 1;
        assert_eq!(
            validate_request(
                IOCTL_GET_CAPS,
                &bytes(&bad),
                size_of::<GetCapsResponse>(),
                7
            )
            .expect_err("size")
            .code,
            ErrorCode::InvalidStructureSize
        );
        let oversized = vec![0u8; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            validate_request(IOCTL_GET_CAPS, &oversized, size_of::<GetCapsResponse>(), 7)
                .expect_err("cap")
                .code,
            ErrorCode::InvalidRange
        );
        let start = StartVmmRequest {
            header: request_header(size_of::<StartVmmRequest>(), 7),
            aperture_limit: 0,
            rendezvous_timeout_tsc: 1,
            device_range_count: 0,
            reserved0: 1,
            reserved1: 0,
        };
        assert_eq!(
            validate_request(
                IOCTL_START_VMM,
                &bytes(&start),
                size_of::<StartVmmResponse>(),
                7
            )
            .expect_err("reserved")
            .code,
            ErrorCode::UnsupportedFlags
        );
        let start = StartVmmRequest {
            header: request_header(size_of::<StartVmmRequest>(), 7),
            aperture_limit: 1 << 39,
            rendezvous_timeout_tsc: 1,
            device_range_count: 1,
            reserved0: 0,
            reserved1: 0,
        };
        let mut start_bytes = bytes(&start);
        start_bytes.extend_from_slice(&bytes(&DevicePhysicalRangeWire {
            start: 0xfec0_0000,
            length: 0x1000,
            reserved: 0,
        }));
        let validated = validate_request(
            IOCTL_START_VMM,
            &start_bytes,
            size_of::<StartVmmResponse>(),
            7,
        )
        .expect("range tail");
        assert_eq!(validated.total_input_size, start_bytes.len());
        let last = start_bytes.len() - 1;
        start_bytes[last] = 1;
        assert_eq!(
            validate_request(
                IOCTL_START_VMM,
                &start_bytes,
                size_of::<StartVmmResponse>(),
                7,
            )
            .expect_err("range reserved")
            .code,
            ErrorCode::UnsupportedFlags
        );
        let batch = ApplyEditBatchRequest {
            header: request_header(size_of::<ApplyEditBatchRequest>(), 7),
            draft: DraftIdWire::default(),
            edit_count: u32::MAX,
            reserved: 0,
        };
        assert!(validate_request(
            IOCTL_APPLY_EDIT_BATCH,
            &bytes(&batch),
            size_of::<ApplyEditBatchResponse>(),
            7
        )
        .is_err());
    }

    #[test]
    fn operation_state_matrix() {
        let session = ControllerSession::new();
        session.acquire(7).expect("owner");
        for descriptor in OPERATIONS {
            for state in [
                LifecycleState::Absent,
                LifecycleState::Preparing,
                LifecycleState::Launching,
                LifecycleState::Running,
                LifecycleState::Quiescing,
                LifecycleState::Stopping,
                LifecycleState::Fatal,
            ] {
                let request = ValidatedRequest {
                    descriptor,
                    header: request_header(
                        descriptor.input_size,
                        if descriptor.zero_nonce { 0 } else { 7 },
                    ),
                    total_input_size: descriptor.input_size,
                };
                assert_eq!(
                    validate_and_begin(&session, request, state).is_ok(),
                    lifecycle_allows(descriptor.code, state)
                );
            }
        }
        let descriptor = operation(IOCTL_STOP_VMM).expect("stop");
        let wrong = ValidatedRequest {
            descriptor,
            header: request_header(descriptor.input_size, 8),
            total_input_size: descriptor.input_size,
        };
        assert_eq!(
            validate_and_begin(&session, wrong, LifecycleState::Running)
                .expect_err("wrong")
                .code,
            ErrorCode::WrongSession
        );
    }

    #[test]
    fn stopped_evidence_remains_readable() {
        assert!(lifecycle_allows(IOCTL_READ_EVENTS, LifecycleState::Absent));
        assert!(lifecycle_allows(
            IOCTL_GET_VCPU_STATE,
            LifecycleState::Absent
        ));
        assert!(!lifecycle_allows(
            IOCTL_APPLY_EDIT_BATCH,
            LifecycleState::Absent
        ));
    }

    #[test]
    fn no_pointer_or_hpa_exposure() {
        let names = include_str!("ioctl.rs");
        let schema = names.split("#[cfg(test)]").next().unwrap_or("");
        for forbidden in [
            "*mut c_void",
            "user_va",
            "kernel_pointer",
            "host_physical_address",
        ] {
            assert!(!schema.contains(forbidden));
        }
        let response = GetVcpuStateResponse::default();
        let encoded = bytes(&response);
        assert!(encoded.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn fuzz_buffered_requests() {
        let mut seed = 0x91e1_0da5_7e11_c0deu64;
        for operation in OPERATIONS {
            for length in 0..=operation
                .input_size
                .saturating_add(operation.trailing_element_size * 3)
            {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let mut input = vec![0u8; length];
                let mut value = seed;
                for byte in &mut input {
                    value = value.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *byte = (value >> 56) as u8;
                }
                let before = input.clone();
                let _ = validate_request(operation.code, &input, operation.output_size, 7);
                assert_eq!(input, before);
            }
        }
    }

    #[test]
    fn event_output_is_whole_records() {
        let request = ReadEventsRequest {
            header: request_header(size_of::<ReadEventsRequest>(), 7),
            cpu_dense_index: 0,
            reserved0: 0,
            max_records: 2,
            after_sequence: 0,
        };
        let output_size =
            size_of::<ReadEventsResponse>() + 2 * hypervisor::telemetry::EVENT_RECORD_BYTES;
        validate_request(IOCTL_READ_EVENTS, &bytes(&request), output_size, 7)
            .expect("whole records");
        assert!(validate_request(IOCTL_READ_EVENTS, &bytes(&request), output_size - 1, 7).is_err());
        assert_eq!(
            output_size - size_of::<ReadEventsResponse>(),
            2 * hypervisor::telemetry::EVENT_RECORD_BYTES
        );
    }
}
