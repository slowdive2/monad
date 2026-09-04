// dispatch returns one result, and only the outer loop acts on it.

use crate::ept::ViewId;
use crate::exit::eventinjection::VmEntryEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDisposition {
    ResumeAndAdvance,
    ResumeWithoutAdvance,
    Inject(VmEntryEvent),
    SwitchPublishedView(ViewId),
    // private lifecycle transition; normal vmcalls never return this.
    Shutdown,
    Fatal(FatalReason),
}

impl ExitDisposition {
    pub const fn advances_rip(self) -> bool {
        matches!(self, Self::ResumeAndAdvance)
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatalReason {
    UnexpectedVmExit = 1,
    InvalidVmcsState = 2,
    VmreadFailure = 3,
    VmwriteFailure = 4,
    InveptFailure = 5,
    RendezvousTimeout = 6,
    RendezvousRollbackFailure = 7,
    MtrrChangedWhileRunning = 8,
    RepeatedEptFault = 9,
    InvalidActiveView = 10,
    InvalidInternalMailbox = 11,
    PartialShutdown = 12,
    CorruptEptHierarchy = 13,
    TripleFault = 14,
    VmEntryFailure = 15,
    UnhandledEptViolation = 16,
    InvalidVcpuState = 17,
}
