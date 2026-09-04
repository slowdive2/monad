//! Extended Page Table construction, validation, and view management.

mod address;
mod backing;
mod builder;
mod entry;
mod manager;
mod mtrr;
mod page;
mod view;
mod walker;

pub use address::*;
pub use backing::*;
pub use builder::*;
pub use entry::{
    EptEntryError, EptLeafSize, EptLevel, EptMemoryType, EptPdEntry, EptPdptEntry, EptPml4Entry,
    EptPtEntry,
};
pub use manager::*;
pub use mtrr::*;
pub use page::*;
pub use view::*;
pub use walker::*;

#[cfg(test)]
pub(crate) struct EptpWriteGuard(usize);

#[cfg(test)]
impl EptpWriteGuard {
    pub(crate) fn new() -> Self {
        Self(crate::arch::intel::vmx::eptp_write_count_for_test())
    }
}

#[cfg(test)]
impl Drop for EptpWriteGuard {
    fn drop(&mut self) {
        assert_eq!(
            crate::arch::intel::vmx::eptp_write_count_for_test(),
            self.0,
            "offline EPT code changed the live EPTP"
        );
    }
}
