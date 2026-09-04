#![no_std]

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
