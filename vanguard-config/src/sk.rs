use std::net::SocketAddr;
use serde::Deserialize;
use vanguard_core::sk::maps::{
    config::*,
};
use vanguard_core::common::ip::*;
use erret_result::*;

use self::serialize::*;

#[derive(Deserialize)]
pub struct SkConf {
    #[serde(deserialize_with = "deserialize_config")]
    pub config: SkConfig,
    
    #[serde(default)]
    pub rules: ,
}

impl SkConf {
    pub fn load(path: &str) -> ErrResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: SkConf = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }
}