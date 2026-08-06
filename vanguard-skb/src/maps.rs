use aya_ebpf::{
    macros::{map},
    maps::{SockMap, SockHash},
    programs::SkMsgContext,
    bindings::{
        sk_msg_md,
        sk_action,
    },
    helpers::bpf_msg_redirect_map,
};

use vanguard_core::common::ip::*;
use vanguard_core::sk::maps::socks::SockKey;

#[map]
pub static mut SOCK_HASH: SockHash<SockKey> = SockHash::with_max_entries(65536, 0);

#[map]
pub static mut SOCK_MAP: SockMap<SockKey> = SockMap::with_max_entries(65536, 0);