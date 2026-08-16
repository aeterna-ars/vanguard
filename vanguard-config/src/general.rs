use std::net::SocketAddr;
use serde::Deserialize;
use vanguard_core::xdp::maps::{
    config::*,
    rules::*,
};
use vanguard_core::common::ip::*;
use erret_result::*;

use self::serialize::*;

#[derive(Deserialize)]
pub struct GeneralConf {
    #[serde(default = "default_iface")]
    pub iface: String,

    pub maps: EbpfMaps,

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

    #[serde(default = "default_pin_path")]
    pub path: String,
}

fn default_pin_path() -> String { "/sys/fs/bpf/vanguard".to_string() }

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