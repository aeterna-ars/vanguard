mod get_map {
    macro_rules! get_map {
        ($bpf:expr, $name:expr, $variant:ident, $type:ty) => {{
            let map = $bpf.take_map($name)
                .ok_or_else(|| VanguardError::EbpfMap("map take error".to_string()))?;
            
            match map {
                aya::maps::Map::$variant(data) => {
                    let map_obj = aya::maps::Map::$variant(data);
                    Ok(<$type>::try_from(map_obj).map_err(|e| VanguardError::EbpfMap(format!("take map error: {e}")))?)
                }
                _ => Err(VanguardError::EbpfMap("try from map error".to_string()).into())
            }
        }};
    }

    pub(crate) use get_map;
}

pub(super) use get_map::get_map;
pub use super::XdpIp;
pub use crate::error::VanguardError;
pub use erret_result::*;
pub use network_types::{
    eth::EtherType,
    ip::IpProto,
};
pub use aya::{
    Ebpf,
    Pod,
    maps::{PerCpuArray, HashMap, MapData, Array}
};