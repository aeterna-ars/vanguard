#![no_std]
#![no_main]

mod parse;
mod inline;
mod maps;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_coarse_ns,
    macros::xdp,
    programs::xdp::XdpContext,
};
use aya_log_ebpf::info;

use crate::maps::{CONFIG, update_stats};

#[xdp]
pub fn core(ctx: XdpContext) -> u32 {
    match try_filter(ctx) {
        Ok(ret) => {
            info!(ctx, "passed");
            update_stats(ret);
            ret
        }
        Err(_) => {
            info!(ctx, "dropped");
            update_stats(1);
            xdp_action::XDP_DROP
        },
    }
}

fn try_filter(ctx: XdpContext) -> Result<u32, u32> {
    let (addr, action) = parse::try_filter_ip(&ctx, 0)?;

    if maps::WHITELIST.get_ptr(&addr).is_some() {
        return Ok(action)
    }

    let now = unsafe { bpf_ktime_get_coarse_ns() };

    let config_ptr = CONFIG.get_ptr_mut(0).unwrap();
    let config = unsafe { &*config_ptr };

    if maps::is_blocked(&addr, now) {
        return Err(xdp_action::XDP_DROP);
    } else if !maps::check_limit(&addr, now, config) {
        maps::block_ip(addr, now, config);
        return Err(xdp_action::XDP_DROP)
    }

    Ok(action)
}