#![no_std]
#![no_main]

mod maps;

use aya_ebpf::{
    macros::sk_msg,
    programs::SkMsgContext,
    bindings::{
        sk_action,
    },
};

use vanguard_core::{
    common::{
        consts::*,
        ip::EbpfIp,
        commons::IpProto
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

    let mut local_ip: EbpfIp = unsafe { core::mem::zeroed() };
    let mut remote_ip: EbpfIp = unsafe { core::mem::zeroed() };

    match msg.family {
        AF_INET => {
            local_ip = EbpfIp::from_v4(msg.local_ip4.to_ne_bytes());
            remote_ip = EbpfIp::from_v4(msg.remote_ip4.to_ne_bytes());
        }
        AF_INET6 => {
            local_ip = EbpfIp::from_v6(msg.local_ip6);
            remote_ip = EbpfIp::from_v6(msg.remote_ip6);
        }
        _ => {}
    }

    let key = SockKey {
        local_ip,
        local_port: msg.local_port,
        remote_ip,
        remote_port: msg.remote_port,
        protocol: IpProto::Tcp,
    };

    SOCK_HASH.redirect_msg(ctx, key, 0);

    Ok(sk_action::SK_PASS)
}