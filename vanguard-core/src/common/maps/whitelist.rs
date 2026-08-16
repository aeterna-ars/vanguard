#[cfg(feature = "userspace")]
use crate::get_map;

#[cfg(feature = "userspace")]
use crate::{common::{commons::*, ip::*}, error::VanguardError};

#[cfg(feature = "userspace")]
pub struct WhitelistMap;

#[cfg(feature = "userspace")]
impl WhitelistMap {
    pub fn get(bpf: &mut Ebpf) -> Result<LpmTrie<MapData, EbpfIp, u8>, VanguardError> {
        get_map!(bpf, "WHITELIST", LpmTrie, LpmTrie<MapData, EbpfIp, u8>)
    }

    pub fn is_white(map: &LpmTrie<MapData, EbpfIp, u8>, ip: EbpfNet) -> bool {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        map.get(&key, 0).is_ok()
    }

    pub fn insert(bpf: &mut Ebpf, ip: EbpfNet) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        if Self::is_white(&map, ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.insert(&key, 0, 0)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }

        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, ip: EbpfNet) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        if !Self::is_white(&map, ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.remove(&key)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }

        Ok(())
    }
}