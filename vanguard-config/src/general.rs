use std::net::SocketAddr;
use serde::Deserialize;
use vanguard_core::common::ip::*;
use erret_result::*;

use crate::serialize_common::*;

#[derive(Deserialize)]
pub struct GeneralConf {
    #[serde(default = "default_iface")]
    pub iface: String,

    #[serde(default)]
    pub maps: EbpfMaps,

    #[serde(default)]
    pub block_config: BlockConfig,

    #[serde(default)]
    pub grpc: GrpcApi,

    #[serde(default, deserialize_with = "deserialize_ip_list")]
    pub blacklist: Vec<EbpfNet>,

    #[serde(default, deserialize_with = "deserialize_ip_list")]
    pub whitelist: Vec<EbpfNet>,
}

impl GeneralConf {
    pub fn load(path: &str) -> ErrResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: GeneralConf = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }
}

fn default_iface() -> String { "eth0".to_string() }

#[derive(Deserialize)]
pub struct EbpfMaps {
    pub pin: bool,
    pub path: String,
}

impl Default for EbpfMaps {
    fn default() -> Self {
        Self {
            pin: false,
            path: "/sys/fs/bpf/vanguard".to_string(),
        }
    }
}

#[derive(Deserialize)]
pub struct GrpcApi {
    pub up: bool,
    pub addr: SocketAddr,
}

impl Default for GrpcApi {
    fn default() -> Self {
        Self {
            up: false,
            addr: "[::1]:8080".parse().unwrap(),
        }
    }
}

#[derive(Deserialize)]
pub struct BlockConfig {
    pub base_block_secs: u32,
    pub max_block_secs: u32,
    pub rep_cooldown_secs: u32,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            base_block_secs: 60,
            max_block_secs: 604800,
            rep_cooldown_secs: 1800,
        }
    }
}