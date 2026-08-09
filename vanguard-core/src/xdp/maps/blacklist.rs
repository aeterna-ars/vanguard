#[cfg(feature = "userspace")]
use crate::common::{common::*, ip::*};

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct XdpBlockEntry {
    pub blocked_until: u64,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpBlockEntry {}

#[cfg(feature = "userspace")]
pub struct BlocklistMap;

#[cfg(feature = "userspace")]
impl BlocklistMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<LpmTrie<MapData, EbpfIp, XdpBlockEntry>> {
        get_map!(bpf, "BLACKLIST", LpmTrie, LpmTrie<MapData, EbpfIp, XdpBlockEntry>)
    }

    fn is_blocked(map: &LpmTrie<MapData, EbpfIp, XdpBlockEntry>, ip: EbpfNet, now: u64) -> bool {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        match map.get(&key, 0) {
            Ok(entry) => now < entry.blocked_until,
            Err(_) => false,
        }
    }

    pub fn block(bpf: &mut Ebpf, ip: EbpfNet, duration: u64) -> ErrResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;
        
        let mut map = Self::get(bpf)?;

        if Self::is_blocked(&map, ip, now) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.insert(&key, XdpBlockEntry { blocked_until: now + duration }, 0)?;
        }

        Ok(())
    }

    pub fn unblock(bpf: &mut Ebpf, ip: EbpfNet) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        map.remove(&key)?;
        Ok(())
    }
}