#[cfg(feature = "userspace")]
use super::common::*;

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[cfg(feature = "userspace")]
use crate::xdp::error::*;

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
        
        let bytes = self.ip.0;
        let is_v4 = bytes[10] == 0xFF 
            && bytes[11] == 0xFF 
            && bytes[0..10].iter().all(|&b| b == 0);

        let prefix = if is_v4 {
            self.prefix_len.saturating_sub(96)
        } else {
            self.prefix_len
        };

        format!("{}/{}", ip_str, prefix)
    }

    fn to_type(s: String) -> ErrResult<Self> {
        use std::net::IpAddr;
        use std::str::FromStr;

        let s = s.trim();
        let mut parts = s.split('/');
        let ip_str = parts.next().ok_or_else(|| VanguardError::Io("empty IP string"))?;

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
                
                let ip = EbpfIp::from_v6(octets);
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
pub struct EbpfIp(pub [u8; 16]);
impl EbpfIp {
    pub fn from_v4(v4: [u8; 4]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[10] = 0xFF;
        bytes[11] = 0xFF;
        bytes[12] = v4[0];
        bytes[13] = v4[1];
        bytes[14] = v4[2];
        bytes[15] = v4[3];
        Self(bytes)
    }

    pub fn from_v6(v6: [u8; 16]) -> Self {
        Self(v6)
    }
}
#[cfg(feature = "userspace")]
unsafe impl Pod for EbpfIp {}

#[cfg(feature = "userspace")]
impl Parse for EbpfIp {
    fn as_str(&self) -> String {
        let bytes = self.0;
        
        let is_v4 = bytes[10] == 0xFF 
            && bytes[11] == 0xFF 
            && bytes[0..10].iter().all(|&b| b == 0);

        if is_v4 {
            format!("{}.{}.{}.{}", bytes[12], bytes[13], bytes[14], bytes[15])
        } else {
            use std::net::Ipv6Addr;
            let ipv6 = Ipv6Addr::from(bytes);
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
            IpAddr::V6(v6) => Ok(EbpfIp::from_v6(v6.octets())),
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
        
        assert_eq!(xdp_ip.0[10], 0xFF);
        assert_eq!(xdp_ip.0[11], 0xFF);
        assert_eq!(xdp_ip.0[12], 192);
        assert_eq!(xdp_ip.0[13], 168);
        assert_eq!(xdp_ip.0[14], 1);
        assert_eq!(xdp_ip.0[15], 1);

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