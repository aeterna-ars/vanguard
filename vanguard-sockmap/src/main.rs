#![no_std]
#![no_main]

use aya_ebpf::{
    bindings,
    helpers::bpf_ktime_get_coarse_ns,
    macros::sk_msg,
    programs::xdp::XdpContext,
};
use aya_log_ebpf::info;

use crate::maps::{CONFIG, update_stats};

#[sk_msg]
pub fn main(ctx: SkMsgContext) -> u32 {
    sk_action::SK_PASS
}