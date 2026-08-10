#[cfg(feature = "userspace")]
use crate::{common::{commons::*, ip::*}, error::VanguardError};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub ip: EbpfNet,
    pad: [u8; 4],
}
#[cfg(feature = "userspace")]
unsafe impl Pod for BlockEvent {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfBlockEntry {
    pub blocked_until: u64,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for EbpfBlockEntry {}

#[cfg(feature = "userspace")]
pub struct BlocklistMap;

#[cfg(feature = "userspace")]
impl BlocklistMap {
    fn get(bpf: &mut Ebpf) -> Result<LpmTrie<MapData, EbpfIp, EbpfBlockEntry>, VanguardError> {
        get_map!(bpf, "BLACKLIST", LpmTrie, LpmTrie<MapData, EbpfIp, EbpfBlockEntry>)
    }

    fn is_blocked(map: &LpmTrie<MapData, EbpfIp, EbpfBlockEntry>, ip: EbpfNet, now: u64) -> bool {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        match map.get(&key, 0) {
            Ok(entry) => now < entry.blocked_until,
            Err(_) => false,
        }
    }

    pub fn block(bpf: &mut Ebpf, ip: EbpfNet, duration: u64) -> Result<(), VanguardError> {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        let now = (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64);
        
        let mut map = Self::get(bpf)?;

        if Self::is_blocked(&map, ip, now) {
            return Ok(());
        } else {
            let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
            map.insert(&key, EbpfBlockEntry { blocked_until: now + duration }, 0)
                .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        }

        Ok(())
    }

    pub fn unblock(bpf: &mut Ebpf, ip: EbpfNet) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);
        map.remove(&key)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        Ok(())
    }
}