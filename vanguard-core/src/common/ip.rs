#[cfg(feature = "userspace")]
use super::common::*;

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[cfg(feature = "userspace")]
use crate::xdp::error::*;

use std::net::*;
use std::str::FromStr;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EbpfNet {
    pub ip: EbpfIp,
    pub prefix_len: u32,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for EbpfNet {}

#[cfg(feature = "userspace")]
impl Parse for EbpfNet {
    fn as_str(&self) -> String {
        let ip_str = self.ip.as_str();
        
        let words = self.ip.0;
        let is_v4 = words[0] == 0 && words[1] == 0 && words[2] == 0;

        let prefix = if is_v4 {
            self.prefix_len.saturating_sub(96)
        } else {
            self.prefix_len
        };

        format!("{}/{}", ip_str, prefix)
    }

    fn to_type(s: String) -> ErrResult<Self> {
        let s = s.trim();
        let mut parts = s.split('/');
        let ip_str = parts.next().ok_or(VanguardError::Io("empty IP string"))?;

        let ip_addr = IpAddr::from_str(ip_str)
            .map_err(|_| VanguardError::Io("invalid IP format"))?;

        let raw_prefix = match parts.next() {
            Some(p_str) => p_str.parse::<u32>().map_err(|_| VanguardError::Io("invalid CIDR prefix"))?,
            None => match ip_addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };

        match ip_addr {
            IpAddr::V4(_) if raw_prefix > 32 => return Err(VanguardError::Io("IPv4 prefix cant be > 32").into()),
            IpAddr::V6(_) if raw_prefix > 128 => return Err(VanguardError::Io("IPv6 prefix cant be > 128").into()),
            _ => {}
        }

        let (xdp_ip, final_prefix) = match ip_addr {
            IpAddr::V4(v4) => {
                let mut octets = v4.octets();
                let bits_to_clear = 32 - raw_prefix;
                if bits_to_clear > 0 {
                    let mask = !0u32 << bits_to_clear;
                    let ip_u32 = u32::from_be_bytes(octets) & mask;
                    octets = ip_u32.to_be_bytes();
                }
                
                let ip = EbpfIp::from_v4(octets);
                (ip, raw_prefix + 96)
            }
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                let mut bits_to_clear = 128 - raw_prefix;
                for i in (0..16).rev() {
                    if bits_to_clear >= 8 {
                        octets[i] = 0;
                        bits_to_clear -= 8;
                    } else if bits_to_clear > 0 {
                        octets[i] &= !0u8 << bits_to_clear;
                        break;
                    } else {
                        break;
                    }
                }
                
                let octets_u32: [u32; 4] = unsafe { core::mem::transmute(octets) };
                let ip = EbpfIp::from_v6(octets_u32);

                (ip, raw_prefix)
            }
        };

        Ok(Self {
            ip: xdp_ip,
            prefix_len: final_prefix,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EbpfIp(pub [u32; 4]);
impl EbpfIp {
    pub fn from_v4(v4: [u8; 4]) -> Self {
        let mut bytes = [0u32; 4];
        bytes[3] = u32::from_be_bytes(v4);
        Self(bytes)
    }

    pub fn from_v6(v6: [u32; 4]) -> Self {
        Self(v6)
    }
}
#[cfg(feature = "userspace")]
unsafe impl Pod for EbpfIp {}

#[cfg(feature = "userspace")]
impl Parse for EbpfIp {
    fn as_str(&self) -> String {
        let words = self.0;
        
        let is_v4 = words[0] == 0 && words[1] == 0 && words[2] == 0;

        if is_v4 {
            let ip_bytes = words[3].to_be_bytes();
            format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3])
        } else {
            let octets_u8: [u8; 16] = unsafe { core::mem::transmute(words) };
            let ipv6 = Ipv6Addr::from(octets_u8);
            ipv6.to_string()
        }
    }

    fn to_type(s: String) -> ErrResult<Self> {
        use std::net::IpAddr;
        use std::str::FromStr;

        let ip = IpAddr::from_str(s.trim())
            .map_err(|_| VanguardError::Io("invalid IP format"))?;

        match ip {
            IpAddr::V4(v4) => Ok(EbpfIp::from_v4(v4.octets())),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let octets_u32: [u32; 4] = unsafe { core::mem::transmute(octets) };
                Ok(EbpfIp::from_v6(octets_u32))
            }
        }
    }
}

#[cfg(test)]
mod test_ip {
    use super::*;

    #[test]
    fn test_ipv4_conversion() {
        let ip_str = "192.168.1.1".to_string();
        
        let xdp_ip = EbpfIp::to_type(ip_str).unwrap();
        
        assert_eq!(xdp_ip.0[0], 0);
        assert_eq!(xdp_ip.0[1], 0);
        assert_eq!(xdp_ip.0[2], 0);
        
        let expected_u32 = u32::from_be_bytes([192, 168, 1, 1]);
        assert_eq!(xdp_ip.0[3], expected_u32);

        assert_eq!(xdp_ip.as_str(), "192.168.1.1");
    }

    #[test]
    fn test_ipv6_conversion() {
        let ip_str = "2001:db8::1".to_string();
        
        let xdp_ip = EbpfIp::to_type(ip_str).unwrap();
        
        assert_eq!(xdp_ip.as_str(), "2001:db8::1");
    }

    #[test]
    fn test_trim_whitespace() {
        let ip_str = "  10.0.0.5 \n".to_string();
        let xdp_ip = EbpfIp::to_type(ip_str).unwrap();
        
        assert_eq!(xdp_ip.as_str(), "10.0.0.5");
    }

    #[test]
    fn test_invalid_ip_format() {
        let bad_ip = "192.168.1.256".to_string();
        assert!(EbpfIp::to_type(bad_ip).is_err());

        let text = "not-an-ip".to_string();
        assert!(EbpfIp::to_type(text).is_err());
        
        let with_port = "127.0.0.1:8080".to_string();
        assert!(EbpfIp::to_type(with_port).is_err());
    }
}

#[cfg(test)]
mod test_net {
    use super::*;

    #[test]
    fn test_ipv4_cidr_round_trip() {
        let net = EbpfNet::to_type("192.168.1.0/24".to_string()).unwrap();

        assert_eq!(net.ip.as_str(), "192.168.1.0");
        assert_eq!(net.as_str(), "192.168.1.0/24");
        
        assert_eq!(net.prefix_len, 120);
    }

    #[test]
    fn test_ipv6_cidr_round_trip() {
        let net = EbpfNet::to_type("2001:db8::/64".to_string()).unwrap();

        assert_eq!(net.ip.as_str(), "2001:db8::");
        assert_eq!(net.as_str(), "2001:db8::/64");
        assert_eq!(net.prefix_len, 64);
    }

    #[test]
    fn test_default_prefix_for_ip_without_cidr() {
        let net = EbpfNet::to_type("10.0.0.5".to_string()).unwrap();

        assert_eq!(net.as_str(), "10.0.0.5/32");
        
        assert_eq!(net.prefix_len, 128);
    }

    #[test]
    fn test_invalid_prefix_is_rejected() {
        assert!(EbpfNet::to_type("192.168.1.0/33".to_string()).is_err());
        assert!(EbpfNet::to_type("2001:db8::/129".to_string()).is_err());
        assert!(EbpfNet::to_type("10.0.0.0/not-a-prefix".to_string()).is_err());
    }
}