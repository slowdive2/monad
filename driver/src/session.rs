use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use hypervisor::error::{ErrorCode, ErrorPhase, MonadError, MonadResult};

#[derive(Debug)]
pub struct ControllerSession {
    nonce: AtomicU64,
    inflight: AtomicU32,
    closing: AtomicBool,
    mutable_busy: AtomicBool,
}

impl ControllerSession {
    pub const fn new() -> Self {
        Self {
            nonce: AtomicU64::new(0),
            inflight: AtomicU32::new(0),
            closing: AtomicBool::new(false),
            mutable_busy: AtomicBool::new(false),
        }
    }

    pub fn acquire(&self, nonce: u64) -> MonadResult<()> {
        if nonce == 0 {
            return Err(session_error(ErrorCode::WrongSession, 0));
        }
        self.nonce
            .compare_exchange(0, nonce, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| session_error(ErrorCode::ControllerBusy, 0))?;
        self.closing.store(false, Ordering::Release);
        Ok(())
    }

    pub fn active_nonce(&self) -> u64 {
        self.nonce.load(Ordering::Acquire)
    }

    pub fn begin(&self, nonce: u64, mutable: bool) -> MonadResult<SessionRequest<'_>> {
        if self.closing.load(Ordering::Acquire) {
            return Err(session_error(ErrorCode::ControllerBusy, 0));
        }
        let active = self.nonce.load(Ordering::Acquire);
        if nonce == 0 || nonce != active {
            return Err(session_error(ErrorCode::WrongSession, nonce));
        }
        self.inflight.fetch_add(1, Ordering::AcqRel);
        if self.closing.load(Ordering::Acquire) || self.nonce.load(Ordering::Acquire) != nonce {
            self.inflight.fetch_sub(1, Ordering::Release);
            return Err(session_error(ErrorCode::WrongSession, nonce));
        }
        if mutable
            && self
                .mutable_busy
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            self.inflight.fetch_sub(1, Ordering::Release);
            return Err(session_error(ErrorCode::ControllerBusy, 0));
        }
        Ok(SessionRequest {
            session: self,
            mutable,
        })
    }

    pub fn begin_close(&self, nonce: u64) -> MonadResult<CloseDrain<'_>> {
        if nonce == 0 || self.nonce.load(Ordering::Acquire) != nonce {
            return Err(session_error(ErrorCode::WrongSession, nonce));
        }
        Ok(self.close_owner())
    }

    /// The successful WDM file owner invokes this only at its final close.
    /// Cleanup cannot release the nonce; Windows has already drained that file's I/O.
    pub(crate) fn close_owner(&self) -> CloseDrain<'_> {
        self.closing.store(true, Ordering::Release);
        CloseDrain { session: self }
    }

    #[cfg(test)]
    fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Acquire)
    }
}

impl Default for ControllerSession {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SessionRequest<'a> {
    session: &'a ControllerSession,
    mutable: bool,
}

impl Drop for SessionRequest<'_> {
    fn drop(&mut self) {
        if self.mutable {
            self.session.mutable_busy.store(false, Ordering::Release);
        }
        self.session.inflight.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Debug)]
pub struct CloseDrain<'a> {
    session: &'a ControllerSession,
}

impl CloseDrain<'_> {
    pub fn is_drained(&self) -> bool {
        self.session.inflight.load(Ordering::Acquire) == 0
    }

    pub fn finish(self) -> MonadResult<()> {
        if !self.is_drained() {
            return Err(session_error(ErrorCode::ControllerBusy, 0));
        }
        let old = self.session.nonce.swap(0, Ordering::AcqRel);
        self.session.closing.store(false, Ordering::Release);
        if old == 0 {
            return Err(session_error(ErrorCode::WrongSession, 0));
        }
        Ok(())
    }
}

fn session_error(code: ErrorCode, detail: u64) -> MonadError {
    MonadError::new(ErrorPhase::Session, code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_quiesces_but_only_final_owner_close_releases() {
        let session = ControllerSession::new();
        session.acquire(7).expect("owner");
        let request = session.begin(7, true).expect("inflight");
        {
            let cleanup = session.begin_close(7).expect("cleanup");
            assert!(!cleanup.is_drained());
        }
        assert_eq!(session.active_nonce(), 7);
        assert!(session.begin(7, false).is_err());
        drop(request); // WDM final close follows this I/O completion.
        let close = session.close_owner();
        assert!(close.is_drained());
        close.finish().expect("final release");
        assert_eq!(session.active_nonce(), 0);
        session.acquire(8).expect("new owner");
    }

    #[test]
    fn session_exclusivity_and_close_race() {
        let session = ControllerSession::new();
        assert!(session.acquire(0).is_err());
        session.acquire(0x1234).expect("first owner");
        assert_eq!(
            session.acquire(0x5678).expect_err("second owner").code,
            ErrorCode::ControllerBusy
        );
        let request = session.begin(0x1234, true).expect("request");
        assert_eq!(session.inflight(), 1);
        assert_eq!(
            session.begin(0x1234, true).expect_err("serialized").code,
            ErrorCode::ControllerBusy
        );
        let close = session.begin_close(0x1234).expect("close");
        assert!(!close.is_drained());
        assert_eq!(
            session.begin(0x1234, false).expect_err("quiesced").code,
            ErrorCode::ControllerBusy
        );
        drop(request);
        assert!(close.is_drained());
        close.finish().expect("release");
        assert_eq!(session.active_nonce(), 0);
        assert_eq!(
            session.begin(0x1234, false).expect_err("stale").code,
            ErrorCode::WrongSession
        );
    }
}
