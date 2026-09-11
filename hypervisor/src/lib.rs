#![no_std]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod arch;
pub mod ept;
pub mod error;
pub mod exit;
pub mod lifecycle;
pub mod logging;
mod memory;
pub mod rendezvous;
pub mod telemetry;
pub mod topology;
pub mod vmm;

// the driver owns the panic handler.
