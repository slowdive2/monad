pub const NO_CPU: u16 = u16::MAX;
pub const NO_OPERATION: u32 = u32::MAX;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorPhase {
    Capability = 1,
    Device = 2,
    Session = 3,
    Topology = 4,
    Mtrr = 5,
    EptBuild = 6,
    DraftEdit = 7,
    Publish = 8,
    Launch = 9,
    Rendezvous = 10,
    Activation = 11,
    ExitHandling = 12,
    Shutdown = 13,
    Telemetry = 14,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidAbiVersion = 1,
    InvalidStructureSize = 2,
    UnsupportedFlags = 3,
    AccessDenied = 4,
    ControllerBusy = 5,
    WrongSession = 6,
    InvalidLifecycleState = 7,
    UnsupportedCapability = 8,
    CompetingHypervisor = 9,
    TooManyProcessors = 10,
    TopologyChanged = 11,
    InvalidRange = 12,
    AddressOverflow = 13,
    MisalignedAddress = 14,
    PhysicalAddressTooWide = 15,
    UnsupportedPermissionCombination = 16,
    UnsupportedMtrrCombination = 17,
    EptAllocationFailure = 18,
    EptVerificationFailure = 19,
    StaleHandle = 20,
    WrongObjectState = 21,
    DraftCapacity = 22,
    PublishedViewCapacity = 23,
    BackingCapacity = 24,
    BackingStillReferenced = 25,
    InvalidCpuSet = 26,
    RendezvousBusy = 27,
    RendezvousTimeout = 28,
    VmreadFailure = 29,
    VmwriteFailure = 30,
    InveptFailure = 31,
    LaunchRollbackFailure = 32,
    ActivationRolledBack = 33,
    ShutdownFailure = 34,
    VmxInstructionFailure = 35,
    InvalidDescriptor = 36,
    InvalidGuestState = 37,
    GenerationOverflow = 38,
    AllocationFailure = 39,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonadError {
    pub phase: ErrorPhase,
    pub code: ErrorCode,
    /// Dense CPU index, or the no-CPU sentinel.
    pub cpu_dense_index: u16,
    /// Always zero; reject nonzero input.
    pub reserved: u16,
    /// Batch index, or the no-operation sentinel.
    pub operation_index: u32,
    /// Stable detail for this code:
    ///
    /// - capability failures name the required feature; impossible controls
    ///   put the field in bits 32..39 and the rejected control mask in bits
    ///   0..31;
    /// - VMX failures put operation in bits 0..7, status in bits 8..15, and the
    ///   instruction error in bits 32..63 (all ones means unavailable);
    /// - address, guest-state, and CPU-set failures use their named detail;
    /// - capacity failures contain the rejected count, physical-width failure
    ///   contains the rejected width, and generation overflow contains the
    ///   previous generation;
    /// - fields rejected for being reserved/nonzero contain the rejected value;
    /// - otherwise detail is zero unless the producing API defines a more
    ///   specific value.
    pub detail: u64,
}

impl MonadError {
    pub const fn new(phase: ErrorPhase, code: ErrorCode, detail: u64) -> Self {
        Self {
            phase,
            code,
            cpu_dense_index: NO_CPU,
            reserved: 0,
            operation_index: NO_OPERATION,
            detail,
        }
    }

    pub const fn on_cpu(mut self, dense_index: u16) -> Self {
        self.cpu_dense_index = dense_index;
        self
    }

    pub const fn at_operation(mut self, operation_index: u32) -> Self {
        self.operation_index = operation_index;
        self
    }
}

pub type MonadResult<T> = core::result::Result<T, MonadError>;
