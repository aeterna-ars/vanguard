use aya_ebpf::{
    macros::{map},
    maps::{SockMap, SockHash},
};

use vanguard_core::common::maps::socks::*;

#[map]
pub static SOCK_HASH: SockHash<SockKey> = SockHash::with_max_entries(65536, 0);

#[map]
pub static SOCK_MAP: SockMap = SockMap::with_max_entries(65536, 0);