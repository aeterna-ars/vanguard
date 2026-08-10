use aya_ebpf::maps::RingBuf;
pub use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruPerCpuHashMap, Array, PerCpuArray, lpm_trie::*},
};

pub use vanguard_core::{
    xdp::maps::{
        config::XdpConfig,
        counter::*,
        rules::{XdpRuleValue, XdpRuleKey}
    },
    common::{
        ip::*,
        maps::{
            blacklist::{BlockEvent, EbpfBlockEntry},
        }
    },
};

#[map]
pub static CONFIG: Array<XdpConfig> = Array::<XdpConfig>::with_max_entries(1, 0);

#[map]
pub static BLOCK_EVENT: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static BLACKLIST: LpmTrie<EbpfIp, EbpfBlockEntry> = LpmTrie::with_max_entries(65536, 0);
#[inline(always)]
pub fn is_blocked(ip: &EbpfIp, now: u64) -> bool {
    let key: Key<EbpfIp> = Key {
        prefix_len: 32,
        data: *ip,
    };

    match unsafe { BLACKLIST.get(&key) } {
        Some(entry) => {
            now < (*entry).blocked_until
        }
        None => false,
    }
}

#[map]
pub static WHITELIST: LpmTrie<EbpfIp, u8> = LpmTrie::with_max_entries(65536, 0); // u8 is nothing
#[inline(always)]
pub fn is_white(ip: &EbpfIp) -> bool {
    let key: Key<EbpfIp> = Key {
        prefix_len: 32,
        data: *ip,
    };

    WHITELIST.get(&key).is_some()
}

#[map]
pub static RULES: HashMap<XdpRuleKey, XdpRuleValue> = HashMap::with_max_entries(1024, 0);

#[map]
pub static PACKET_COUNTER: LruPerCpuHashMap<EbpfIp, XdpCounter> = LruPerCpuHashMap::with_max_entries(65536, 0);
#[inline(always)]
pub fn check_limit(ip: &EbpfIp, now: u64, config: &XdpConfig) -> bool {
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