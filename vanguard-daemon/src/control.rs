// revamping

use std::{
    collections::HashMap,
    sync::Arc
};

use erret_result::ErrResult;
use vanguard_core::{
    common::{
        commons::Parse,
        ip::*,
        maps::blacklist::BlocklistMap,
    },
    brevno::*,
    get_map,
};

use tokio::{
    sync::Mutex,
    time::{Duration, sleep},
};

use aya::maps::{MapData, lpm_trie::*};

const BASE_BLOCK_SECS: u64 = 60;
const MAX_BLOCK_SECS: u64 = 86400 * 7;

const REPUTATION_COOLDOWN_SECS: u64 = 3600;

struct IpReputation {
    pub violation_count: u32,
    pub is_banned: bool,
}

pub struct BlackManager {
    bpf: Arc<Mutex<aya::Ebpf>>,
    blacklist: aya::maps::LpmTrie<aya::maps::MapData, EbpfIp, u8>,
    reputation_db: Arc<Mutex<HashMap<EbpfIp, IpReputation>>>,
}

impl BlackManager {
    pub async fn new(
        bpf: Arc<Mutex<aya::Ebpf>>,
    ) -> ErrResult<Self> {
        let reputation_db = Arc::new(Mutex::new(HashMap::new()));
        
        let db_clone = Arc::clone(&reputation_db);
        Self::cooldown(db_clone);

        let mut bpf_lock = bpf.lock().await;
        let blacklist = get_map!(&mut *bpf_lock, "BLACKLIST", LpmTrie, LpmTrie<MapData, EbpfIp, u8>)?;
        drop(bpf_lock);

        Ok(Self { bpf, blacklist, reputation_db })
    }

    async fn block_ip(&mut self, ip: EbpfIp) -> ErrResult<()> {
        let key: Key<EbpfIp> = Key::new(32, ip);

        if self.blacklist.get(&key, 0).is_err() {
            let mut reps = self.reputation_db.lock().await;
            let violation_count = reps.entry(ip).or_insert(0);
            *violation_count += 1;

            let exponent = violation_count.saturating_sub(1);
            let mut block_secs = BASE_BLOCK_SECS.saturating_mul(2u64.pow(exponent));
            
            if block_secs > MAX_BLOCK_SECS {
                block_secs = MAX_BLOCK_SECS;
            }

            let net = EbpfNet {
                ip,
                prefix_len: 32,
            };

            let mut bpf_lock = self.bpf.lock().await;
            BlocklistMap::block(&mut bpf_lock, net)?;
            drop(bpf_lock);

            self.blacklist.insert(&key, 1, 0)?;
            info!(
                "IP {:?} blocked; violation count: {}; blocked on: {} seconds",
                ip.as_str(), violation_count, block_secs
            );

            let mut blacklist_clone = self.blacklist.clone();
            let reputation_db_clone = Arc::clone(&self.reputation_db);

            Self::unblock_timer(self.bpf, block_secs, blacklist_clone, ip).await?;
        }

        Ok(())
    }

    async fn unblock_timer(
        bpf: Arc<Mutex<aya::Ebpf>>,
        block_secs: u64,
        blacklist: aya::maps::HashMap<aya::maps::MapData, EbpfIp, u8>,
        reputation_db: Arc<Mutex<HashMap<EbpfIp, IpReputation>>>,
        ip: EbpfIp,
    ) -> ErrResult<()> {
        tokio::spawn(async move {
            sleep(Duration::from_secs(block_secs)).await;

            let net = EbpfNet {
                ip,
                prefix_len: 32,
            };

            let mut bpf_lock = bpf.lock().await;
            if let Ok(_) = BlocklistMap::unblock(&mut bpf_lock, net) {
                info!("IP {:?} unblocked", ip.as_str());
            }
            drop(bpf_lock);

            let mut db = reputation_db.lock().await;
            if let Some(rep) = db.get_mut(&ip) {
                rep.is_banned = false;
            }
            drop(db);
        });

        Ok(())
    }

    fn cooldown(
        db: Arc<Mutex<HashMap<EbpfIp, IpReputation>>>,
    ) {
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(REPUTATION_COOLDOWN_SECS)).await;
                let mut db = db.lock().await;
                
                db.retain(|_ip, rep| {
                    if !rep.is_banned && rep.violation_count > 0 {
                        rep.violation_count -= 1;
                    }
                    rep.violation_count > 0
                });
            }
        });
    }
}