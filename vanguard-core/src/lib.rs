#![cfg_attr(not(feature = "userspace"), no_std)]

pub mod maps;

#[cfg(feature = "userspace")]
pub mod config;

#[cfg(feature = "userspace")]
pub mod error;

pub use network_types;

#[cfg(feature = "userspace")]
pub use erret_result;

#[cfg(feature = "userspace")]
pub use brevno;