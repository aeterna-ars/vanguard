#![no_std]
#![no_main]

mod maps;

use aya_ebpf::{
    macros::{map, sk_msg},
    maps::SockMap,
    programs::SkMsgContext,
    bindings::{
        sk_msg_md,
        sk_action,
    },
    helpers::bpf_msg_redirect_map,
};

use vanguard_core::{
    common::{
        consts::*,
        ip::EbpfIp,
        common::IpProto
    },
    sk::maps::socks::SockKey,
};

use crate::maps::*;

#[sk_msg]
pub fn main(ctx: SkMsgContext) -> u32 {
    match try_egress(ctx) {
        Ok(act) => act,
        Err(act) => act,
    }
}

#[inline(always)]
fn try_egress(ctx: SkMsgContext) -> Result<u32, u32> {
    let msg = unsafe { &*ctx.msg };

    let mut local_ip = [0u8; 16];
    let mut remote_ip = [0u8; 16];

    match msg.family {
        AF_INET => {
            local_ip = EbpfIp::from_v4(msg.local_ip4.to_ne_bytes())?;
            remote_ip = EbpfIp::from_v6(msg.remote_ip6.to_ne_bytes())?;
        }
        AF_INET6 => {
            local_ip = EbpfIp::from_v6(msg.local_ip6.to_ne_bytes())?;
            remote_ip = EbpfIp::from_v6(msg.remote_ip6.to_ne_bytes())?;
        }
    }

    let mut key = SockKey {
        local_ip: EbpfIp(local_ip),
        local_port: msg.local_port,
        remote_ip: EbpfIp(remote_ip),
        remote_port: msg.remote_port,
        protocol: IpProto::Tcp,
    };

    unsafe {
        match SOCK_HASH.redirect_msg(&ctx, &key, 0) {
            Ok(_) => Ok(aya_ebpf::bindings::sk_action::SK_PASS),
            Err(_) => Ok(aya_ebpf::bindings::sk_action::SK_PASS),
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}