#![cfg_attr(not(feature = "userspace"), no_std)]

pub mod maps;

#[cfg(feature = "userspace")]
pub mod config;

#[cfg(feature = "userspace")]
pub mod error;