use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruPerCpuHashMap, Array, PerCpuArray},
};

pub use vanguard_common::maps2::xdp_maps::*;

#[map]
pub static CONFIG: Array<XdpConfig> = Array::<XdpConfig>::with_max_entries(1, 0);

#[map]
pub static BLACKLIST: HashMap<XdpIp, XdpBlockEntry> = HashMap::with_max_entries(65536, 0);
#[inline(always)]
pub fn block_ip(ip: &XdpIp, now: u64, config: &XdpConfig) {
    let entry = XdpBlockEntry {
        blocked_until: config.block_time + now,
    };
    let _ = BLACKLIST.insert(ip, &entry, 0);
}
#[inline(always)]
pub fn is_blocked(ip: &XdpIp, now: u64) -> bool {
    match unsafe { BLACKLIST.get(ip) } {
        Some(entry) => {
            if now < (*entry).blocked_until {
                true
            } else {
                let _ = BLACKLIST.remove(ip);
                false
            }
        }
        None => false,
    }
}

#[map]
pub static WHITELIST: HashMap<XdpIp, u8> = HashMap::with_max_entries(65536, 0); // u8 is nothing

#[map]
pub static RULES: HashMap<XdpRuleKey, XdpRuleValue> = HashMap::with_max_entries(65536, 0);

#[map]
pub static PACKET_COUNTER: LruPerCpuHashMap<XdpIp, XdpCounter> = LruPerCpuHashMap::with_max_entries(65536, 0);
pub const RESET_INTERVAL: u64 = 1_000_000_000;
#[inline(always)]
pub fn check_limit(ip: &XdpIp, now: u64, config: &XdpConfig) -> bool {
    unsafe {
        if let Some(ptr) = PACKET_COUNTER.get_ptr_mut(ip) {
            let counter = &mut *ptr;

            if now - counter.last_reset > RESET_INTERVAL {
                counter.count = 0;
                counter.last_reset = now;
            }

            if counter.count >= config.rate_limit {
                return false;
            }

            counter.count += 1;
        } else {
            let new_counter = XdpCounter {
                count: 1,
                last_reset: now,
            };
            let _ = PACKET_COUNTER.insert(ip, &new_counter, 0);
        }

        true
    }
}

#[map]
pub static STATS: PerCpuArray<GlobalStats> = PerCpuArray::<GlobalStats>::with_max_entries(1, 0);
#[repr(C)]
pub struct GlobalStats {
    pub total: u64,
    pub dropped: u64,
    pub passed: u64,
    pub tx: u64,
    pub redirected: u64,
}
#[inline(always)]
pub fn update_stats(action: u32) {
    let stats = STATS.get_ptr_mut(0);
    if let Some(stats) = stats {
        let stats = unsafe { &mut *stats };
        stats.total += 1;
        match action {
            1 => stats.dropped += 1,
            2 => stats.passed += 1,
            3 => stats.tx += 1,
            4 => stats.redirected += 1,
            _ => {}
        }
    }
}