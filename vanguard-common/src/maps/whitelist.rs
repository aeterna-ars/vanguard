use super::common::*;

pub struct WhitelistMap;
impl WhitelistMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<HashMap<MapData, XdpIp, u8>> {
        get_map!(bpf, "WHITELIST", HashMap, HashMap<MapData, XdpIp, u8>)
    }

    fn is_white(map: &HashMap<MapData, u128, u8>, ip: u128) -> bool {
        match map.get(&ip, 0) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn insert(bpf: &mut Ebpf, ip: u128) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        if Self::is_white(&map, ip) {
            return Ok(());
        } else {
            map.insert(&ip, 0, 0)?;
        }

        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, ip: u128) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        if !Self::is_white(&map, ip) {
            return Ok(());
        } else {
            map.remove(&ip)?;
        }

        Ok(())
    }
}