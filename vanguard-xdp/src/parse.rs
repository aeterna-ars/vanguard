use aya_ebpf::{
    bindings::xdp_action,
    programs::XdpContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr, IpProto},
    tcp::{TcpHdr, TCP_HDR_LEN},
    udp::UdpHdr,
};

use crate::inline::ptr_at;
use crate::maps::{RULES, RuleKey};

pub fn try_filter_ip(ctx: &XdpContext, offset: usize) -> Result<(u128, u32), u32> {
    let ethhdr: *const EthHdr = match ptr_at(&ctx, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Err(xdp_action::XDP_PASS),
    };

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            let iphdr: *const Ipv4Hdr = match ptr_at(&ctx, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };
            let src = u32::from_be_bytes(unsafe { (*iphdr).src_addr });
            let ip_len = unsafe { (*iphdr).ihl() as usize * 4 };
            let proto = match unsafe { (*iphdr).proto() } {
                Ok(p) => p,
                Err(_) => {
                    return Err(xdp_action::XDP_DROP)
                }
            };

            let port = try_filter_port(&ctx, ip_len, proto)?;

            let key = RuleKey {
                ip: src as u128,
                port,
                eth: EtherType::Ipv4,
                proto,
                pad: 0,
            };

            if let Some(act) = unsafe { RULES.get(&key) } {
                return Ok((src as u128, act.action as u32));
            }

            Ok((src as u128, xdp_action::XDP_PASS))
        },
        Ok(EtherType::Ipv6) => {
            let iphdr: *const Ipv6Hdr = match ptr_at(&ctx, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };
            let src = u128::from_be_bytes(unsafe { (*iphdr).src_addr });
            let ip_len = Ipv6Hdr::LEN;
            let proto = match unsafe { (*iphdr).next_hdr() } {
                Ok(p) => p,
                Err(_) => {
                    return Err(xdp_action::XDP_DROP)
                }
            };

            let port = try_filter_port(&ctx, ip_len, proto)?;

            let key = RuleKey {
                ip: src,
                port,
                eth: EtherType::Ipv6,
                proto,
                pad: 0,
            };

            if let Some(act) = unsafe { RULES.get(&key) } {
                return Ok((src, act.action as u32));
            }

            Ok((src, xdp_action::XDP_PASS))
        },
        _ => {
            return Err(xdp_action::XDP_DROP)
        }
    }
}

fn try_filter_port(ctx: &XdpContext, offset: usize, protocol: IpProto) -> Result<u16, u32> {
    match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = match ptr_at(ctx, TCP_HDR_LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_PASS),
            };
            let port = u16::from_be_bytes(unsafe { (*tcphdr).source });

            return Ok(port)
        },
        IpProto::Udp => {
            let udphdr: *const UdpHdr = match ptr_at(ctx, UdpHdr::LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_PASS),
            };
            let port = u16::from_be_bytes(unsafe { (*udphdr).src });

            return Ok(port)
        },
        _ => {
            return Err(xdp_action::XDP_DROP);
        }
    }
}