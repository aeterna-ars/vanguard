use std::net::SocketAddr;
use serde::Deserialize;
use erret_result::*;
use super::maps::{
    config::*,
    ip::*,
    rules::*,
};

use self::serialize::*;

#[derive(Deserialize)]
pub struct VanguardConfig {
    #[serde(default = "default_iface")]
    pub iface: String,

    #[serde(deserialize_with = "deserialize_config")]
    pub config: XdpConfig,

    #[serde(default)]
    pub blacklist: Vec<BlockConfig>,

    #[serde(default, deserialize_with = "deserialize_ip_list")]
    pub whitelist: Vec<XdpIp>,

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
pub struct BlockConfig {
    #[serde(deserialize_with = "deserialize_ip")]
    pub ip: XdpIp,

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

mod serialize {
    use crate::maps::*;
    use super::*;
    use serde::{Deserialize, Deserializer, de::Error};

    #[derive(Debug, Clone, Deserialize)]
    pub struct XdpConfigWrapper {
        pub rate_limit: u32,
        pub block_time: u64,
    }

    impl TryFrom<XdpConfigWrapper> for XdpConfig {
        type Error = ErrRet;

        fn try_from(wrapper: XdpConfigWrapper) -> Result<Self, Self::Error> {
            Ok(XdpConfig {
                rate_limit: wrapper.rate_limit,
                block_time: wrapper.block_time,
            })
        }
    }

    pub fn deserialize_config<'de, D>(deserializer: D) -> Result<XdpConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapper: XdpConfigWrapper = Deserialize::deserialize(deserializer)?;
        Ok(wrapper.try_into().map_err(|e| D::Error::custom(format!("{e}")))?)
    }

    #[derive(Clone, Deserialize)]
    pub struct XdpRuleKeyWrapper {
        pub ip: String,
        pub port: u16,
        pub eth: String,
        pub proto: String,
    }

    impl TryFrom<XdpRuleKeyWrapper> for XdpRuleKey {
        type Error = ErrRet;

        fn try_from(w: XdpRuleKeyWrapper) -> Result<Self, Self::Error> {
            Ok(XdpRuleKey {
                ip: XdpIp::to_type(w.ip)?,
                port: w.port,
                eth: EtherType::to_type(w.eth)?,
                proto: IpProto::to_type(w.proto)?,
            })
        }
    }

    pub fn deserialize_rkey<'de, D>(deserializer: D) -> Result<XdpRuleKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapper = XdpRuleKeyWrapper::deserialize(deserializer)?;
        Ok(wrapper.try_into().map_err(|e| D::Error::custom(format!("{e}")))?)
    }

    #[derive(Clone, Deserialize)]
    pub struct XdpRuleValueWrapper {
        pub action: String,
        pub redirect: XdpRuleKeyWrapper,
    }

    impl TryFrom<XdpRuleValueWrapper> for XdpRuleValue {
        type Error = ErrRet;

        fn try_from(w: XdpRuleValueWrapper) -> Result<Self, Self::Error> {
            let redirect_key: XdpRuleKey = w.redirect.try_into()?;
            
            Ok(XdpRuleValue {
                action: XdpRuleAction::to_type(w.action)?,
                redirect: redirect_key,
            })
        }
    }

    pub fn deserialize_rval<'de, D>(deserializer: D) -> Result<XdpRuleValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapper = XdpRuleValueWrapper::deserialize(deserializer)?;
        Ok(wrapper.try_into().map_err(|e| D::Error::custom(format!("{e}")))?)
    }

    pub fn deserialize_ip<'de, D>(deserializer: D) -> Result<XdpIp, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        XdpIp::to_type(s).map_err(D::Error::custom)
    }

    pub fn deserialize_ip_list<'de, D>(deserializer: D) -> Result<Vec<XdpIp>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ips: Vec<String> = Deserialize::deserialize(deserializer)?;
        ips.into_iter()
            .map(|s| XdpIp::to_type(s).map_err(D::Error::custom))
            .collect()
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
        assert_eq!(cfg.config.block_time, 1000);
        assert_eq!(cfg.grpc.addr.to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.grpc.up, true);
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
      to:
        ip: "1.1.1.1"
        port: 53
        eth: "ipv4"
        proto: "udp"
        "#;

        let cfg: VanguardConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(cfg.config.rate_limit, 1000);
        assert_eq!(cfg.config.block_time, 1000);
        assert_eq!(cfg.grpc.addr.to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.grpc.up, true);
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
        assert_eq!(cfg.config.block_time, 1000);
        assert_eq!(cfg.grpc.addr.to_string(), "[::1]:8080");
        assert_eq!(cfg.grpc.up, false);
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