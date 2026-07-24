use super::common::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpBlockEntry {
    pub blocked_until: u64,
}
unsafe impl Pod for XdpBlockEntry {}

pub struct BlocklistMap;
impl BlocklistMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<HashMap<MapData, u128, XdpBlockEntry>> {
        get_map!(bpf, "BLOCKLIST", HashMap, HashMap<MapData, u128, XdpBlockEntry>)
    }

    fn is_blocked(map: &HashMap<MapData, u128, BlockEntry>, ip: u128, now: u64) -> bool {
        match map.get(&ip, 0) {
            Ok(entry) => now < entry.blocked_until,
            Err(_) => false,
        }
    }

    pub fn block(bpf: &mut Ebpf, ip: u128, duration: u64) -> ErrResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;
        
        let mut map = Self::get(bpf)?;

        if Self::is_blocked(&map, ip, now) {
            return Ok(());
        } else {
            map.insert(&ip, &XdpBlockEntry { blocked_until: now + duration }, 0)?;
        }

        Ok(())
    }

    pub fn unblock(bpf: &mut Ebpf, ip: u128) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;
        map.remove(&ip)?;
        Ok(())
    }
}