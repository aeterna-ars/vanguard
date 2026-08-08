#![no_std]
#![no_main]

mod maps;

use aya_ebpf::{
    macros::{stream_parser, stream_verdict},
    maps::SockMap,
    programs::SkBuffContext,
    bindings::sk_action,
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

#[stream_parser]
pub fn parser(ctx: SkBuffContext) -> u32 {
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
pub fn verdict(ctx: SkBuffContext) -> u32 {
    match try_verdict(ctx) {
        Ok(act) => act,
        Err(act) => act,
    }
}

#[inline(always)]
fn try_verdict(ctx: SkBuffContext) -> Result<u32, u32> {
    let skb = ctx.as_ptr();

    if skb.is_null() {
        return Ok(sk_action::SK_PASS);
    }

    unsafe {

    }

    Ok(sk_action::SK_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}