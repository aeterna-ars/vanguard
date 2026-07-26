use std::net::SocketAddr;

use serde::Deserialize;

use super::maps::{
    parse::*,
    *,
};

use erret_result::*;

#[derive(Deserialize)]
pub struct VanguardConfig {
    #[serde(default = "default_iface")]
    pub iface: String,

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
pub struct Rule {
    #[serde(deserialize_with = "deserialize_rkey")]
    key: XdpRuleKey,

    #[serde(deserialize_with = "deserialize_rvalue")]
    value: XdpRuleValue,
}

#[derive(Deserialize)]
pub struct BlockConfig {
    #[serde(deserialize_with = "deserialize_ip")]
    pub ip: XdpIp,

    #[serde(default)]
    pub blocked_until: u64,
}

#[derive(Deserialize)]
pub struct GrpcApi {
    pub up: bool,

    #[serde(deserialize_with = "deserialize_ip")]
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
    use network_types::{
        eth::EtherType,
        ip::IpProto,
    };

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
    fn test_deserialize_ip_v4() {
        let ip = deserialize_ip("192.168.1.1").unwrap();
        assert_eq!(
            ip.0,
            u128::from_be_bytes([
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0xff, 0xff,
                192, 168, 1, 1,
            ])
        );
    }

    #[test]
    fn test_deserialize_ip_v6() {
        let ip = deserialize_ip("2001:db8::1").unwrap();
        let expected = u128::from_be_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        assert_eq!(ip.0, expected);
    }

    #[test]
    fn test_deserialize_ip_with_cidr() {
        let ip = deserialize_ip("192.168.1.0/24").unwrap();
        assert_eq!(
            ip.0,
            u128::from_be_bytes([
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0xff, 0xff,
                192, 168, 1, 0,
            ])
        );
    }

    #[test]
    fn test_deserialize_ip_invalid() {
        let result = deserialize_ip("not-an-ip");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_eth_ipv4() {
        let eth = deserialize_eth("ipv4").unwrap();
        match eth {
            EtherType::Ipv4 => {}
            _ => panic!("Expected Ipv4"),
        }
    }

    #[test]
    fn test_deserialize_eth_ipv6() {
        let eth = deserialize_eth("ipv6").unwrap();
        match eth {
            EtherType::Ipv6 => {}
            _ => panic!("Expected Ipv6"),
        }
    }

    #[test]
    fn test_deserialize_eth_arp() {
        let eth = deserialize_eth("arp").unwrap();
        match eth {
            EtherType::Arp => {}
            _ => panic!("Expected Arp"),
        }
    }

    #[test]
    fn test_deserialize_eth_invalid() {
        let result = deserialize_eth("unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_proto_tcp() {
        let proto = deserialize_proto("tcp").unwrap();
        match proto {
            IpProto::Tcp => {}
            _ => panic!("Expected Tcp"),
        }
    }

    #[test]
    fn test_deserialize_proto_udp() {
        let proto = deserialize_proto("udp").unwrap();
        match proto {
            IpProto::Udp => {}
            _ => panic!("Expected Udp"),
        }
    }

    #[test]
    fn test_deserialize_proto_icmp() {
        let proto = deserialize_proto("icmp").unwrap();
        match proto {
            IpProto::Icmp => {}
            _ => panic!("Expected Icmp"),
        }
    }

    #[test]
    fn test_deserialize_proto_icmpv6() {
        let proto = deserialize_proto("icmpv6").unwrap();
        match proto {
            IpProto::Ipv6Icmp => {}
            _ => panic!("Expected Ipv6Icmp"),
        }
    }

    #[test]
    fn test_deserialize_proto_any() {
        let proto = deserialize_proto("any").unwrap();
        match proto {
            IpProto::Larp => {} // Unsupported
            _ => panic!("Expected Larp (unsupported)"),
        }
    }

    #[test]
    fn test_deserialize_proto_invalid() {
        let result = deserialize_proto("unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_action_drop() {
        let action = deserialize_action("drop").unwrap();
        match action {
            XdpRuleAction::DROP => {}
            _ => panic!("Expected DROP"),
        }
    }

    #[test]
    fn test_deserialize_action_pass() {
        let action = deserialize_action("pass").unwrap();
        match action {
            XdpRuleAction::PASS => {}
            _ => panic!("Expected PASS"),
        }
    }

    #[test]
    fn test_deserialize_action_redirect() {
        let action = deserialize_action("redirect").unwrap();
        match action {
            XdpRuleAction::REDIRECT => {}
            _ => panic!("Expected REDIRECT"),
        }
    }

    #[test]
    fn test_deserialize_action_abort() {
        let action = deserialize_action("abort").unwrap();
        match action {
            XdpRuleAction::ABORTED => {}
            _ => panic!("Expected ABORTED"),
        }
    }

    #[test]
    fn test_deserialize_action_tx() {
        let action = deserialize_action("tx").unwrap();
        match action {
            XdpRuleAction::TX => {}
            _ => panic!("Expected TX"),
        }
    }

    #[test]
    fn test_deserialize_action_invalid() {
        let result = deserialize_action("unknown");
        assert!(result.is_err());
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

    fn deserialize_ip(input: &str) -> Result<XdpIp, String> {
        use serde::de::value::{Error as ValueError, StringDeserializer};
        let deserializer = StringDeserializer::<ValueError>::new(input.to_string());
        super::deserialize_ip(deserializer)
            .map_err(|e| e.to_string())
    }

    fn deserialize_eth(input: &str) -> Result<EtherType, String> {
        use serde::de::value::{Error as ValueError, StringDeserializer};
        let deserializer = StringDeserializer::<ValueError>::new(input.to_string());
        super::deserialize_eth(deserializer)
            .map_err(|e| e.to_string())
    }

    fn deserialize_proto(input: &str) -> Result<IpProto, String> {
        use serde::de::value::{Error as ValueError, StringDeserializer};
        let deserializer = StringDeserializer::<ValueError>::new(input.to_string());
        super::deserialize_proto(deserializer)
            .map_err(|e| e.to_string())
    }

    fn deserialize_action(input: &str) -> Result<XdpRuleAction, String> {
        use serde::de::value::{Error as ValueError, StringDeserializer};
        let deserializer = StringDeserializer::<ValueError>::new(input.to_string());
        super::deserialize_action(deserializer)
            .map_err(|e| e.to_string())
    }
}