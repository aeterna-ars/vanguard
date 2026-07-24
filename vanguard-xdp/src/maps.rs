use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruPerCpuHashMap, Array, PerCpuArray},
};

use network_types::{
    eth::EtherType,
    ip::IpProto,
};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ip(pub [u8; 16]);
impl Ip {
    #[inline(always)]
    pub fn from_v4(v4: [u8; 4]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[10] = 0xFF;
        bytes[11] = 0xFF;
        bytes[12] = v4[0];
        bytes[13] = v4[1];
        bytes[14] = v4[2];
        bytes[15] = v4[3];
        Self(bytes)
    }

    #[inline(always)]
    pub fn from_v6(v6: [u8; 16]) -> Self {
        Self(v6)
    }
}

#[map]
pub static CONFIG: Array<Config> = Array::<Config>::with_max_entries(1, 0);
#[repr(C)]
pub struct Config {
    pub rate_limit: u32,
    pub block_time: u64,
}

#[map]
pub static BLACKLIST: HashMap<Ip, BlockEntry> = HashMap::with_max_entries(65536, 0);
#[repr(C)]
pub struct BlockEntry {
    pub blocked_until: u64,
}
#[inline(always)]
pub fn block_ip(ip: &Ip, now: u64, config: &Config) {
    let entry = BlockEntry {
        blocked_until: config.block_time + now,
    };
    let _ = BLACKLIST.insert(ip, &entry, 0);
}
#[inline(always)]
pub fn is_blocked(ip: &Ip, now: u64) -> bool {
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
pub static WHITELIST: HashMap<Ip, u8> = HashMap::with_max_entries(65536, 0); // u8 is nothing

#[map]
pub static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(65536, 0);
#[repr(C)]
pub struct RuleKey {
    pub ip: Ip,
    pub port: u16,
    pub eth: EtherType,
    pub proto: IpProto,
}
#[repr(C)]
pub struct RuleValue {
    pub action: RuleAction,
    pub to: RuleKey,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub enum RuleAction {
    ABORTED = 0,
    DROP = 1,
    PASS = 2,
    TX = 3,
    REDIRECT = 4,
}

#[map]
pub static PACKET_COUNTER: LruPerCpuHashMap<Ip, Counter> = LruPerCpuHashMap::with_max_entries(65536, 0);
pub const RESET_INTERVAL: u64 = 1_000_000_000;
#[repr(C)]
pub struct Counter {
    pub count: u32,
    pub last_reset: u64,
}
#[inline(always)]
pub fn check_limit(ip: &Ip, now: u64, config: &Config) -> bool {
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
            let new_counter = Counter {
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