use super::common::*;
use erret_result::ErrResult;
use crate::error::*;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XdpIp(pub [u8; 16]);
impl XdpIp {
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
unsafe impl Pod for XdpIp {}

impl Parse for XdpIp {
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
            IpAddr::V4(v4) => Ok(XdpIp::from_v4(v4.octets())),
            IpAddr::V6(v6) => Ok(XdpIp::from_v6(v6.octets())),
        }
    }
}