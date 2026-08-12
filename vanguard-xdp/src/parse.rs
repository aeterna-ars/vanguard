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

use crate::maps::*;

use core::mem;

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let (start, end) = (ctx.data(), ctx.data_end());
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(unsafe { &*ptr })
}

#[inline(always)]
pub fn try_parse_ip(ctx: &XdpContext, offset: usize) -> Result<(EbpfIp, u32), u32> {
    let ethhdr: *const EthHdr = match ptr_at(ctx, offset) {
        Ok(hdr) => hdr,
        Err(_) => return Err(xdp_action::XDP_DROP),
    };

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            let iphdr: *const Ipv4Hdr = match ptr_at(ctx, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };
            let src = EbpfIp::from_v4(unsafe { (*iphdr).src_addr });
            let ip_len = unsafe { (*iphdr).ihl() as usize * 4 };
            let proto = match unsafe { (*iphdr).proto() } {
                Ok(p) => p,
                Err(_) => {
                    return Err(xdp_action::XDP_DROP)
                }
            };

            let port = try_parse_proto(ctx, ip_len, proto)?;

            let key = XdpRuleKey {
                ip: src,
                port,
                eth: EtherType::Ipv4,
                proto,
            };

            if let Some(act) = unsafe { RULES.get(key) } {
                return Ok((src, act.action as u32));
            }

            return Ok((src, xdp_action::XDP_PASS))
        },
        Ok(EtherType::Ipv6) => {
            let iphdr: *const Ipv6Hdr = match ptr_at(ctx, EthHdr::LEN) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };
            let src = EbpfIp::from_v6(unsafe { core::mem::transmute::<[u8; 16], [u32; 4]>((*iphdr).src_addr) });
            let ip_len = Ipv6Hdr::LEN;
            let proto = match unsafe { (*iphdr).next_hdr() } {
                Ok(p) => p,
                Err(_) => {
                    return Err(xdp_action::XDP_DROP)
                }
            };

            let port = try_parse_proto(ctx, ip_len, proto)?;

            let key = XdpRuleKey {
                ip: src,
                port,
                eth: EtherType::Ipv6,
                proto,
            };

            if let Some(act) = unsafe { RULES.get(key) } {
                return Ok((src, act.action as u32));
            }

            return Ok((src, xdp_action::XDP_PASS))
        },
        _ => {
            return Err(xdp_action::XDP_PASS)
        }
    }

    #[allow(unreachable_code)]
    Err(xdp_action::XDP_PASS)
}

#[inline(always)]
fn try_parse_proto(ctx: &XdpContext, offset: usize, protocol: IpProto) -> Result<EbpfPort, u32> {
    match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = match ptr_at(ctx, TCP_HDR_LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };

            let port = u16::from_be_bytes( unsafe { (*tcphdr).source } );
            
            return Ok(EbpfPort(port))
        },
        IpProto::Udp => {
            let udphdr: *const UdpHdr = match ptr_at(ctx, UdpHdr::LEN + offset) {
                Ok(hdr) => hdr,
                Err(_) => return Err(xdp_action::XDP_DROP),
            };

            let port = u16::from_be_bytes( unsafe { (*udphdr).src } );

            return Ok(EbpfPort(port))
        },
        _ => {
            return Err(xdp_action::XDP_PASS);
        }
    }

    #[allow(unreachable_code)]
    Err(xdp_action::XDP_PASS)
}