#[cfg(feature = "userspace")]
pub use aya::{
    Ebpf,
    Pod,
    maps::{PerCpuArray, HashMap, MapData, Array, lpm_trie::*, SockHash, SockMap}
};

pub use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CntConfig {
    pub rate_limit: u32,
    pub interval: u64,
    pub max_tokens: u16,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for CntConfig {}

#[cfg(feature = "userspace")]
impl CntConfig {
    pub fn new(rate_limit: u32, burst_limit: u16) -> Self {
        let interval = if rate_limit > 0 {
            1_000_000_000u64 / (rate_limit as u64) / 4
        } else {
            u64::MAX
        };

        Self {
            rate_limit,
            interval,
            max_tokens: burst_limit,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TBucketCounter {
    pub state: u64, // 1st 32bit - time, 2nd 32 - tokens
    pub total: u64,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for TBucketCounter {}