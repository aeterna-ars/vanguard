pub mod general;
pub mod skb;
pub mod msg;
pub mod xdp;

pub mod serialize_common {
    use serde::{Deserialize, Deserializer, de::Error};
    use vanguard_core::common::{
        commons::*,
        ip::*
    };

    pub fn deserialize_ip<'de, D>(deserializer: D) -> Result<EbpfNet, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        EbpfNet::to_type(s).map_err(D::Error::custom)
    }

    pub fn deserialize_ip_list<'de, D>(deserializer: D) -> Result<Vec<EbpfNet>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ips: Vec<String> = Deserialize::deserialize(deserializer)?;
        ips.into_iter()
            .map(|s| EbpfNet::to_type(s).map_err(D::Error::custom))
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