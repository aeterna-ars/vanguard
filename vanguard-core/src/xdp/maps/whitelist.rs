#[cfg(feature = "userspace")]
use crate::common::{common::*, ip::*};

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[cfg(feature = "userspace")]
pub struct WhitelistMap;

#[cfg(feature = "userspace")]
impl WhitelistMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<LpmTrie<MapData, EbpfIp, u8>> {
        get_map!(bpf, "WHITELIST", LpmTrie, LpmTrie<MapData, EbpfIp, u8>)
    }

    fn is_white(map: &LpmTrie<MapData, EbpfIp, u8>, ip: EbpfNet) -> bool {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        match map.get(&key, 0) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn insert(bpf: &mut Ebpf, ip: EbpfNet) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        if Self::is_white(&map, ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.insert(&key, 0, 0)?;
        }

        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, ip: EbpfNet) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        if !Self::is_white(&map, ip) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.remove(&key)?;
        }

        Ok(())
    }
}