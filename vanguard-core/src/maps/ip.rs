use super::common::*;

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

#[cfg(feature = "userspace")]
pub use self::parse::*;
pub mod parse {
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::*;
    use serde::{Deserialize, Deserializer, de::Error};

    pub fn parse_ip(s: String) -> std::result::Result<XdpIp, &'static str> {
        let ip = IpAddr::from_str(s.trim())
            .map_err(|_| "Invalid IP address format")?;

        match ip {
            IpAddr::V4(v4) => {
                Ok(XdpIp::from_v4(v4.octets()))
            }
            IpAddr::V6(v6) => {
                Ok(XdpIp::from_v6(v6.octets()))
            }
        }
    }

    pub fn parse_ip_arg(s: &str) -> std::result::Result<XdpIp, std::io::Error> {
        parse_ip(s.to_string()).map_err(|e| std::io::Error::other(e.to_string()))
    }
    
    pub fn deserialize_ip<'de, D>(deserializer: D) -> Result<XdpIp, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_ip(s).map_err(|e| D::Error::custom(format!("{e}")))?)
    }
    
    pub fn deserialize_ip_list<'de, D>(deserializer: D) -> Result<Vec<XdpIp>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let list = Vec::<String>::deserialize(deserializer)?;
    
        list.iter()
            .map(|s| parse_ip(s.to_string())
                .map_err(|e| D::Error::custom(format!("{e}"))))
            .collect()
    }
}