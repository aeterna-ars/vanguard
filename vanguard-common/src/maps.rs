use std::convert::TryFrom;

use aya::{
    Ebpf, Pod, maps::{Array, HashMap, MapData, PerCpuArray},
};

use network_types::{
    eth::EtherType,
    ip::IpProto,
};

use serde::Deserialize;

use crate::parse::serialize::*;
use crate::error::VanguardError;

use erret_result::*;

use clap::*;

#[repr(C)]
#[derive(Clone, Copy, Deserialize)]
pub struct Ip(pub u128);

macro_rules! get_map {
    ($bpf:expr, $name:expr, $variant:ident, $type:ty) => {{
        let map = $bpf.take_map($name)
            .ok_or_else(|| VanguardError::EbpfMap("map take error".to_string()))?;
        
        match map {
            aya::maps::Map::$variant(data) => {
                let map_obj = aya::maps::Map::$variant(data);
                Ok(<$type>::try_from(map_obj).map_err(|e| VanguardError::EbpfMap(format!("take map error: {e}")))?)
            }
            _ => Err(VanguardError::EbpfMap("try from map error".to_string()).into())
        }
    }};
}

#[repr(C)]
#[derive(Clone, Copy, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub rate_limit: u32,
    #[serde(default)]
    pub block_time: u64,
}
unsafe impl Pod for Config {}

pub struct ConfigMap;
impl ConfigMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<Array<MapData, Config>> {
        get_map!(bpf, "CONFIG", Array, Array<MapData, Config>)
    }

    pub fn read(bpf: &mut Ebpf) -> ErrResult<Config> {
        let map = Self::get(bpf)?;
        let mp = map.get(&0, 0)?;

        Ok(mp)
    }

    pub fn write(bpf: &mut Ebpf, config: Config) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;
        map.set(0, config, 0)?;

        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Deserialize)]
pub struct BlockEntry {
    pub blocked_until: u64,
}
unsafe impl Pod for BlockEntry {}

pub struct BlocklistMap;
impl BlocklistMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<HashMap<MapData, u128, BlockEntry>> {
        get_map!(bpf, "BLOCKLIST", HashMap, HashMap<MapData, u128, BlockEntry>)
    }

    fn is_blocked(map: &HashMap<MapData, u128, BlockEntry>, ip: u128, now: u64) -> bool {
        match map.get(&ip, 0) {
            Ok(entry) => now < entry.blocked_until,
            Err(_) => false,
        }
    }

    pub fn block(bpf: &mut Ebpf, ip: u128, duration: u64) -> ErrResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos() as u64;
        
        let mut map = Self::get(bpf)?;

        if Self::is_blocked(&map, ip, now) {
            return Ok(());
        } else {
            map.insert(&ip, &BlockEntry { blocked_until: now + duration }, 0)?;
        }

        Ok(())
    }

    pub fn unblock(bpf: &mut Ebpf, ip: u128) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;
        map.remove(&ip)?;
        Ok(())
    }
}

pub struct WhitelistMap;
impl WhitelistMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<HashMap<MapData, u128, u8>> {
        get_map!(bpf, "WHITELIST", HashMap, HashMap<MapData, u128, u8>)
    }

    fn is_white(map: &HashMap<MapData, u128, u8>, ip: u128) -> bool {
        match map.get(&ip, 0) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn insert(bpf: &mut Ebpf, ip: u128) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        if Self::is_white(&map, ip) {
            return Ok(());
        } else {
            map.insert(&ip, 0, 0)?;
        }

        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, ip: u128) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        if !Self::is_white(&map, ip) {
            return Ok(());
        } else {
            map.remove(&ip)?;
        }

        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Deserialize, Args)]
pub struct Rule {
    #[command(flatten)]
    pub key: RuleKey,

    #[command(flatten)]
    pub value: RuleValue,
}

#[repr(C)]
#[derive(Clone, Copy, Deserialize, Args)]
pub struct RuleKey {
    #[serde(deserialize_with = "deserialize_ip")]
    pub ip: Ip,

    #[arg(short, long)]
    pub port: u16,

    #[serde(deserialize_with = "deserialize_eth")]
    #[arg(short, long)]
    pub eth: EtherType,

    #[serde(deserialize_with = "deserialize_proto")]
    #[arg(short, long)]
    pub proto: IpProto,
}
unsafe impl Pod for RuleKey {}

#[repr(C)]
#[derive(Clone, Copy, Deserialize, Args)]
pub struct RuleValue {
    #[serde(deserialize_with = "deserialize_action")]
    #[arg(short, long)]
    pub action: RuleAction,

    #[serde(default)]
    #[arg(short, long)]
    pub to: Option<RuleKey>,
}
unsafe impl Pod for RuleValue {}

#[repr(u32)]
#[derive(Clone, Copy, Subcommand)]
pub enum RuleAction {
    ABORTED = 0,
    DROP = 1,
    PASS = 2,
    TX = 3,
    REDIRECT = 4,
}

impl TryFrom<u32> for RuleAction {
    type Error = VanguardError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RuleAction::ABORTED),
            1 => Ok(RuleAction::DROP),
            2 => Ok(RuleAction::PASS),
            3 => Ok(RuleAction::TX),
            4 => Ok(RuleAction::REDIRECT),
            _ => Err(VanguardError::Io("invalid rule action"))
        }
    }
}

pub struct RulesMap;
impl RulesMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<HashMap<MapData, RuleKey, RuleValue>> {
        get_map!(bpf, "RULES", HashMap, HashMap<MapData, RuleKey, RuleValue>)
    }

    pub fn add(bpf: &mut Ebpf, key: RuleKey, value: RuleValue) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;
        map.insert(&key, value, 0)?;
        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, key: RuleKey) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;
        map.remove(&key)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GlobalStats {
    pub total: u64,
    pub dropped: u64,
    pub passed: u64,
    pub tx: u64,
    pub redirected: u64,
}
unsafe impl Pod for GlobalStats {}
impl GlobalStats {
    fn get(bpf: &mut Ebpf) -> ErrResult<PerCpuArray<MapData, GlobalStats>> {
        get_map!(bpf, "STATS", PerCpuArray, PerCpuArray<MapData, GlobalStats>)
    }

    pub fn get_total(bpf: &mut Ebpf) -> ErrResult<Self> {
        let stats_map = Self::get(bpf)
            .map_err(|e| VanguardError::EbpfMap(format!("Failed to get STATS map: {:?}", e)))?;
        
        let per_cpu_values = stats_map.get(&0, 0)?; 

        let mut total_stats = GlobalStats {
            total: 0,
            dropped: 0,
            passed: 0,
            tx: 0,
            redirected: 0,
        };

        for cpu_stat in per_cpu_values.iter() {
            total_stats.total += cpu_stat.total;
            total_stats.dropped += cpu_stat.dropped;
            total_stats.passed += cpu_stat.passed;
            total_stats.tx += cpu_stat.tx;
            total_stats.redirected += cpu_stat.redirected;
        }

        Ok(total_stats)
    }
}