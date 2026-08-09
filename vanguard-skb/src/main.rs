#![no_std]
#![no_main]

mod maps;
use maps::*;

use aya_ebpf::{
    bindings::sk_action,
    macros::{stream_parser, stream_verdict},
    programs::SkBuffContext,
};

use vanguard_core::{
    common::{
        consts::*,
        ip::EbpfIp,
        common::IpProto
    },
    sk::maps::socks::SockKey,
};

#[stream_parser]
fn parser(ctx: SkBuffContext) -> u32 {
    match try_parse(ctx) {
        Ok(act) => act,
        Err(act) => act,
    }
}

#[inline(always)]
fn try_parse(ctx: SkBuffContext) -> Result<u32, u32> {
    Ok(ctx.len())
}

#[stream_verdict]
fn verdict(ctx: SkBuffContext) -> u32 {
    match try_verdict(ctx) {
        Ok(act) => act,
        Err(act) => act,
    }
}

#[inline(always)]
fn try_verdict(ctx: SkBuffContext) -> Result<u32, u32> {
    let buf = &ctx.skb;

    let mut local_ip: EbpfIp = unsafe { core::mem::zeroed() };
    let mut remote_ip: EbpfIp = unsafe { core::mem::zeroed() };

    match buf.family() {
        AF_INET => {
            local_ip = EbpfIp::from_v4(buf.local_ipv4().to_ne_bytes());
            remote_ip = EbpfIp::from_v4(buf.remote_ipv4().to_ne_bytes());
        }
        AF_INET6 => {
            local_ip = EbpfIp::from_v6(*buf.local_ipv6());
            remote_ip = EbpfIp::from_v6(*buf.remote_ipv6());
        }
        _ => {}
    }

    let key = SockKey {
        local_ip,
        local_port: buf.local_port(),
        remote_ip,
        remote_port: buf.remote_port(),
        protocol: IpProto::Tcp,
    };

    SOCK_HASH.redirect_skb(ctx, key, 0);

    Ok(sk_action::SK_PASS)
}