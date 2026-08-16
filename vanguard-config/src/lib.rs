pub mod general;
pub mod sk;
pub mod msg;
pub mod xdp;

use std::net::SocketAddr;
use serde::Deserialize;
use vanguard_core::xdp::maps::{
    config::*,
    rules::*,
};
use vanguard_core::common::ip::*;
use erret_result::*;

#[derive(Deserialize)]
pub struct VanguardConfig {
    #[serde(default = "default_iface")]
    pub iface: String,

    pub maps: EbpfMaps,

    #[serde(deserialize_with = "deserialize_config")]
    pub config: XdpConfig,

    #[serde(default)]
    pub blacklist: Vec<BlockConfig>,

    #[serde(default, deserialize_with = "deserialize_ip_list")]
    pub whitelist: Vec<EbpfNet>,

    #[serde(default)]
    pub rules: Vec<Rule>,

    #[serde(default)]
    pub grpc: GrpcApi,
}

impl VanguardConfig {
    pub fn load(path: &str) -> ErrResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: VanguardConfig = serde_yaml::from_str(&content)?;
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
pub struct BlockConfig {
    #[serde(deserialize_with = "deserialize_ip")]
    pub ip: EbpfNet,

    #[serde(default)]
    pub blocked_until: u64,
}

#[derive(Deserialize)]
pub struct Rule {
    #[serde(deserialize_with = "deserialize_rkey")]
    pub key: XdpRuleKey,

    #[serde(deserialize_with = "deserialize_rval")]
    pub value: XdpRuleValue,
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

#[cfg(test)]
mod test_cfg {
    use super::*;

    #[test]
    fn test_parse_from_file() {
        let yaml = "../vanguard.yml";

        let cfg: VanguardConfig = VanguardConfig::load(yaml).unwrap();

        assert_eq!(cfg.config.rate_limit, 1000);
        assert_eq!(cfg.config.burst_limit, 1000);
        assert_eq!(cfg.grpc.addr.to_string(), "0.0.0.0:8080");
        assert!(!cfg.grpc.up);
        assert_eq!(cfg.blacklist.len(), 2);
        assert_eq!(cfg.whitelist.len(), 3);
        assert_eq!(cfg.rules.len(), 3);
    }

    #[test]
    fn test_parse_full_config() {
        let yaml = r#"
grpc:
  up: true
  addr: "0.0.0.0:8080"

config:
  rate_limit: 1000
  block_time: 1000

blacklist:
- ip: "1.2.3.4"
  blocked_until: 1234567890
- ip: "5.6.7.8"

whitelist:
- "192.168.1.1"
- "10.0.0.0/24"
- "::1"

rules:
  - key:
      ip: "5.6.7.8"
      port: 80
      eth: "ipv4"
      proto: "tcp"
    value:
      action: "drop"

  - key:
      ip: "2001:db8::1"
      port: 443
      eth: "ipv6"
      proto: "tcp"
    value:
      action: "pass"

  - key:
      ip: "0.0.0.0"
      port: 53
      eth: "ipv4"
      proto: "udp"
    value:
      action: "redirect"
      redirect:
        ip: "1.1.1.1"
        port: 53
        eth: "ipv4"
        proto: "udp"
        "#;

        let cfg: VanguardConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(cfg.config.rate_limit, 1000);
        assert_eq!(cfg.config.burst_limit, 1000);
        assert_eq!(cfg.grpc.addr.to_string(), "0.0.0.0:8080");
        assert!(!cfg.grpc.up);
        assert_eq!(cfg.blacklist.len(), 2);
        assert_eq!(cfg.whitelist.len(), 3);
        assert_eq!(cfg.rules.len(), 3);
    }

    #[test]
    fn test_load_config_from_file() {
        let yaml = r#"
config:
  rate_limit: 500
  block_time: 1000

blacklist:
  - ip: "10.0.0.1"
    blocked_until: 9999999999

whitelist:
  - "8.8.8.8"

rules:
  - key:
      ip: "1.1.1.1"
      port: 53
      eth: "ipv4"
      proto: "udp"
    value:
      action: "drop"
        "#;

        let temp_file = std::env::temp_dir().join("vanguard_test_config.yaml");
        std::fs::write(&temp_file, yaml).unwrap();

        let cfg = VanguardConfig::load(temp_file.to_str().unwrap()).unwrap();

        assert_eq!(cfg.config.rate_limit, 500);
        assert_eq!(cfg.config.burst_limit, 1000);
        assert_eq!(cfg.grpc.addr.to_string(), "[::1]:8080");
        assert!(!cfg.grpc.up);
        assert_eq!(cfg.blacklist.len(), 1);
        assert_eq!(cfg.whitelist.len(), 1);
        assert_eq!(cfg.rules.len(), 1);

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_missing_fields_use_defaults() {
        let yaml = r#"
config:
  rate_limit: 100
  block_time: 100
        "#;

        let cfg: VanguardConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(cfg.config.rate_limit, 100);
        assert!(cfg.blacklist.is_empty());
        assert!(cfg.whitelist.is_empty());
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn test_invalid_yaml_returns_error() {
        let yaml = r#"
packet_rate_limit_per_sec: "not-a-number"
        "#;

        let result: Result<VanguardConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }
}