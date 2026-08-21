use std::net::SocketAddr;
use serde::Deserialize;
use vanguard_core::msg::maps::config::MsgConfig;
use vanguard_core::skb::maps::{
    config::*,
};
use vanguard_core::common::ip::*;
use erret_result::*;

use self::serialize::*;

#[derive(Deserialize)]
pub struct MsgConf {
    #[serde(deserialize_with = "deserialize_config")]
    pub config: MsgConfig,
    
    #[serde(default)]
    pub rules: ,
}

impl MsgConf {
    pub fn load(path: &str) -> ErrResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: MsgConf = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }
}