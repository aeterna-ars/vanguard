pub use network_types::{
    eth::EtherType,
    ip::IpProto,
};

#[cfg(feature = "userspace")]
pub use aya::{
    Ebpf,
    Pod,
    maps::{PerCpuArray, HashMap, MapData, Array, lpm_trie::*, SockHash, SockMap}
};

use crate::error::VanguardError;

#[cfg(feature = "userspace")]
#[macro_export]
macro_rules! get_map {
    ($bpf:expr, $name:expr, $variant:ident, $type:ty) => {{
        let map = $bpf.take_map($name)
            .ok_or_else(|| $crate::error::VanguardError::EbpfMapError("map take error".to_string()))?;
        
        match map {
            aya::maps::Map::$variant(data) => {
                let map_obj = aya::maps::Map::$variant(data);
                Ok(<$type>::try_from(map_obj).map_err(|e| $crate::error::VanguardError::EbpfMapError(format!("take map error: {e}")))?)
            }
            _ => Err($crate::error::VanguardError::EbpfMapError("try from map error".to_string()).into())
        }
    }};
}

#[cfg(feature = "userspace")]
pub trait Parse: Sized {
    fn as_str(&self) -> Result<String, VanguardError>;
    fn to_type(s: String) -> Result<Self, VanguardError>;
}

#[cfg(feature = "userspace")]
impl Parse for EtherType {
    fn as_str(&self) -> Result<String, VanguardError> {
        match self {
            Self::Ipv4 => Ok("ipv4".to_string()),
            Self::Ipv6 => Ok("ipv6".to_string()),
            Self::Arp => Ok("arp".to_string()),
            _ => Err(VanguardError::IoError("useless ethertype")),
        }
    }

    fn to_type(s: String) -> Result<Self, VanguardError> {
        match s.to_lowercase().trim() {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            "arp" => Ok(Self::Arp),
            _ => Err(VanguardError::IoError("useless ethertype")),
        }
    }
}

#[cfg(feature = "userspace")]
impl Parse for IpProto {
    fn as_str(&self) -> Result<String, VanguardError> {
        match self {
            Self::Icmp => Ok("icmp".to_string()),
            Self::Ipv4 => Ok("ipv4".to_string()),
            Self::Tcp => Ok("tcp".to_string()),
            Self::Udp => Ok("udp".to_string()),
            Self::Ipv6 => Ok("ipv6".to_string()),
            Self::Ipv6Icmp => Ok("ipv6icmp".to_string()),
            _ => Err(VanguardError::IoError("useless ipproto")),
        }
    }

    fn to_type(s: String) -> Result<Self, VanguardError> {
        match s.to_lowercase().trim() {
            "icmp" => Ok(Self::Icmp),
            "ipv4" => Ok(Self::Ipv4),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "ipv6" => Ok(Self::Ipv6),
            "ipv6icmp" | "icmpv6" => Ok(Self::Ipv6Icmp),
            _ => Err(VanguardError::IoError("useless ipproto")),
        }
    }
}