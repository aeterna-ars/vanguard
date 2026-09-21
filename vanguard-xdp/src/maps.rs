use aya_ebpf::{
    macros::map,
    maps::{
        HashMap,
        Array,
        PerCpuArray,
        lpm_trie::*,
        BloomFilter,
        LruHashMap,
        RingBuf
    },
};

pub use vanguard_core::{
    xdp::maps::{
        counter::*,
        rules::{XdpRuleValue, XdpRuleKey},
        stats::XdpGlobalStats,
    },
    common::{
        ip::*,
        maps::{
            accesslist::{BlockEvent, AccessValue},
        }
    },
};

#[map] pub static RINGBUF: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

#[map] pub static CONFIG: Array<XdpConfig> = Array::<XdpConfig>::with_max_entries(1, 0);

#[map] pub static ACCESS_LIST: LpmTrie<EbpfIp, AccessValue> = LpmTrie::with_max_entries(65536, 0);
#[map] pub static BLOOM_RULES: BloomFilter<EbpfIp> = BloomFilter::with_max_entries(65536, 0);

#[map] pub static RULES: HashMap<XdpRuleKey, XdpRuleValue> = HashMap::with_max_entries(1024, 0);

#[map]
pub static STATS: PerCpuArray<XdpGlobalStats> = PerCpuArray::<XdpGlobalStats>::with_max_entries(1, 0);
#[inline(always)]
pub fn update_stats(action: u32) {
    let stats = STATS.get_ptr_mut(0);
    if let Some(stats) = stats {
        let stats = unsafe { &mut *stats };
        match action {
            1 => stats.dropped += 1,
            2 => stats.passed += 1,
            3 => stats.tx += 1,
            4 => stats.redirected += 1,
            _ => {}
        }
    }
}

#[map]
pub static PACKET_COUNTER: LruHashMap<EbpfIp, TBucketCounter> = LruHashMap::with_max_entries(65536, 0);
#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn check_limit(
    ip: &EbpfIp,
    now_ns: u64,
    config: CntConfig,
    map: LruHashMap<EbpfIp, TBucketCounter>,
) -> bool {
    let now_shifted: u64 = now_ns >> 16;
    let config_interval_shifted = (config.interval >> 16).max(1);
    
    if let Some(ptr) = map.get_ptr_mut(ip) {
        let mut current_raw = counter.state.load(Ordering::Relaxed);

        for _ in 0..10 {
            let last_update = current_raw >> 16;
            let mut tokens = (current_raw & 0xFFFF) as u32;

            if now_shifted > last_update {
                let elapsed = now_shifted - last_update;
                // Твоё оригинальное деление дельты на интервал из конфига (тут деление легально, т.к. это дельта)
                let generated_tokens = (elapsed / config_interval_shifted) as u32;
                
                if generated_tokens > 0 {
                    tokens = core::cmp::min(config.max_tokens as u32, tokens + generated_tokens);
                }
            }

            if tokens < 1 {
                return false; // Забанен, токенов нет
            }

            tokens -= 1;

            // Запаковываем обратно: время сдвигаем влево на 16 бит, токены пихаем в хвост
            let new_raw = (now_shifted << 16) | (tokens as u64 & 0xFFFF);

            match counter.state.compare_exchange_weak(
                current_raw,
                new_raw,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current_raw = actual,
            }
        }
        return true; 

        if now_ns > cnt.last_update {
            let elapsed_ns = now_ns - cnt.last_update;
            let generated_tokens = elapsed_ns / config.interval;
            if generated_tokens > 0 {
                cnt.tokens = core::cmp::min(config.max_tokens, cnt.tokens + generated_tokens);
                cnt.last_update += generated_tokens * config.interval;
            }
        } else {
            cnt.last_update = now_ns;
        }

        if cnt.tokens >= 1 {
            cnt.tokens -= 1;
            return true;
        }

        false
    } else {
        let new_state = XdpPacketCounter {
            tokens: config.max_tokens.saturating_sub(1),
            last_update: now_ns,
        };
        let _ = PACKET_COUNTER.insert(ip, new_state, 0);
        true
    }
}

#[inline(always)]
pub fn check_limit(ip: &EbpfIp, now_ns: u64, config: &XdpConfig) -> bool {
    // 1. Сжимаем время, чтобы влезло в 32 бита
    let now_shifted = (now_ns >> 16) as u32;
    // Конфиг интервала тоже нужно пересчитать с учетом сдвига времени в юзерспейсе!
    let config_interval_shifted = (config.interval >> 16).max(1) as u32;

    if let Some(counter) = PACKET_COUNTER.get(ip) {
        // Загружаем текущее состояние атомарно
        let mut current_state = counter.state.load(Ordering::Relaxed);

        // Крутим CAS-цикл (Compare-And-Swap), пока успешно не обновим состояние
        for _ in 0..10 { // Ограничиваем цикл для верификатора
            // Распаковываем u64 на два u32
            let mut tokens = (current_state >> 32) as u32;
            let mut last_update = (current_state & 0xFFFFFFFF) as u32;

            if now_shifted > last_update {
                let elapsed = now_shifted - last_update;
                let generated_tokens = elapsed / config_interval_shifted;
                
                if generated_tokens > 0 {
                    tokens = core::cmp::min(config.max_tokens, tokens + generated_tokens);
                    last_update += generated_tokens * config_interval_shifted;
                }
            } else {
                last_update = now_shifted;
            }

            // Проверяем, есть ли токены
            if tokens < 1 {
                return false; // Токенов нет, пакет дропаем (CAS делать не нужно)
            }

            // Списываем один токен
            tokens -= 1;

            // Запаковываем обратно в u64
            let new_state = ((tokens as u64) << 32) | (last_update as u64);

            // Пытаемся атомарно обновить. Если другое ядро успело вклиниться — 
            // exchange вернет Err с новым актуальным значением, и мы уйдем на следующий круг.
            match counter.state.compare_exchange_weak(
                current_state,
                new_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true, // Успешно обновили, пакет легитимный!
                Err(actual) => current_state = actual, // Обломались, обновили current_state и крутим дальше
            }
        }
        
        // Если за 10 итераций из-за дикой гонки не смогли обновиться — 
        // лучше пропустить пакет (или дропнуть), чтобы не вешать ядро
        return true; 
    } else {
        // Если IP зашел впервые
        let initial_tokens = config.max_tokens.saturating_sub(1);
        let initial_state = ((initial_tokens as u64) << 32) | (now_shifted as u64);
        
        let new_state = XdpPacketCounter {
            state: AtomicU64::new(initial_state),
        };
        
        let _ = PACKET_COUNTER.insert(ip, &new_state, 0);
        true
    }
}