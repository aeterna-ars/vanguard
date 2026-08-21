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
};

use tokio::{
    sync::Mutex,
    time::{Duration, sleep},
};

use aya::{
    Ebpf,
    maps::{
        MapData,
        lpm_trie::*
    }
};

struct IpReputation {
    pub violation_count: u32,
    pub is_banned: bool,
}

pub struct BlackManager {
    bpf: Arc<Ebpf>,
    blacklist: Arc<LpmTrie<MapData, EbpfIp, u8>>,
    reputation_db: Arc<HashMap<EbpfIp, IpReputation>>,
}

impl BlackManager {
    pub async fn new(
        bpf: Arc<aya::Ebpf>,
    ) -> ErrResult<Self> {
        let reputation_db = Arc::new(Mutex::new(HashMap::new()));

        let blacklist = BlocklistMap::get(&mut bpf)?;
        
        let db_clone = Arc::clone(&reputation_db);
        Self::cooldown(db_clone);

        Ok(Self { bpf, blacklist: Arc::new(blacklist), reputation_db })
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

            BlocklistMap::block(&mut self.bpf, net)?;

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
        &mut self,
        block_secs: u64,
        ip: EbpfIp,
    ) -> ErrResult<()> {
        tokio::spawn(async move {
            sleep(Duration::from_secs(block_secs)).await;

            let net = EbpfNet {
                ip,
                prefix_len: 32,
            };

            if let Ok(_) = BlocklistMap::unblock(&mut self.bpf, net) {
                info!("IP {:?} unblocked", ip.as_str());
            }

            if let Some(rep) = db.get_mut(&ip) {
                rep.is_banned = false;
            }
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