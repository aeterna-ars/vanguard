use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruPerCpuHashMap, Array, PerCpuArray},
};

use network_types::{
    eth::EtherType,
    ip::IpProto,
};

use vanguard_common::maps::{RuleAction, GlobalStats};

#[map]
pub static CONFIG: Array<Config> = Array::<Config>::with_max_entries(1, 0);
#[repr(C)]
pub struct Config {
    pub rate_limit: u32,
    pub block_time: u64,
}

pub const RESET_INTERVAL: u64 = 1_000_000;

#[map]
pub static BLACKLIST: HashMap<u128, BlockEntry> = HashMap::with_max_entries(65536, 0);
#[repr(C)]
pub struct BlockEntry {
    pub blocked_until: u64,
}
pub fn block_ip(ip: u128, now: u64, config: &Config) {
    let entry = BlockEntry {
        blocked_until: config.block_time + now,
    };
    let _ = BLACKLIST.insert(ip, &entry, 0);
}
pub fn is_blocked(ip: &u128, now: u64) -> bool {
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
pub static WHITELIST: HashMap<u128, u8> = HashMap::with_max_entries(65536, 0);

#[map]
pub static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(65536, 0);
#[repr(C)]
pub struct RuleKey {
    pub ip: u128,
    pub port: u16,
    pub eth: EtherType,
    pub proto: IpProto,
    pub pad: u8,
}
#[repr(C)]
pub struct RuleValue {
    pub action: RuleAction,
    pub to: RuleKey,
}

#[map]
pub static PACKET_COUNTER: LruPerCpuHashMap<u128, Counter> = LruPerCpuHashMap::with_max_entries(65536, 0);
#[repr(C)]
pub struct Counter {
    pub count: u32,
    pub last_reset: u64,
}
pub fn check_limit(ip: &u128, now: u64, config: &Config) -> bool {
    unsafe {
        match PACKET_COUNTER.get_ptr_mut(ip) {
            Some(ptr) => {
                let counter = &mut *ptr;

                if now - counter.last_reset > RESET_INTERVAL {
                    counter.count = 0;
                    counter.last_reset = now;
                }

                if counter.count >= config.rate_limit {
                    return false;
                }

                counter.count += 1;

                true
            }
            None => {
                let new_counter = Counter {
                    count: 1,
                    last_reset: now,
                };

                let _ = PACKET_COUNTER.insert(ip, &new_counter, 0);
                true
            }
        }
    }
}

#[map]
pub static STATS: PerCpuArray<GlobalStats> = PerCpuArray::<GlobalStats>::with_max_entries(1, 0);
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