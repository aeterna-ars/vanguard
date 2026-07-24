use std::{
    net::{
        IpAddr,
        Ipv6Addr
    },
    str::FromStr
};

use erret_result::*;

use crate::maps::*;

use network_types::{
    eth::EtherType,
    ip::IpProto,
};

use crate::error::VanguardError;

use serde::de::Error as SerdeDeError;

impl From<Ip> for XdpIp {
    fn from(ip: Ip) -> Self {
        Self(ip.0.to_be_bytes())
    }
}

impl From<Config> for XdpConfig {
    fn from(cfg: Config) -> Self {
        XdpConfig {
            rate_limit: cfg.rate_limit,
            block_time: cfg.block_time,
        }
    }
}

impl From<RuleAction> for XdpRuleAction {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::ABORTED => XdpRuleAction::ABORTED,
            RuleAction::DROP => XdpRuleAction::DROP,
            RuleAction::PASS => XdpRuleAction::PASS,
            RuleAction::TX => XdpRuleAction::TX,
            RuleAction::REDIRECT => XdpRuleAction::REDIRECT,
        }
    }
}

impl From<RuleKey> for XdpRuleKey {
    fn from(key: RuleKey) -> Self {
        XdpRuleKey {
            ip: XdpIp::from(key.ip),
            port: key.port,
            eth: key.eth,
            proto: key.proto,
        }
    }
}

impl From<RuleValue> for XdpRuleValue {
    fn from(val: RuleValue) -> Self {
        match val.to {
            Some(target_key) => XdpRuleValue {
                action: XdpRuleAction::from(val.action),
                to: XdpRuleKey::from(target_key),
            },
            None => XdpRuleValue {
                action: XdpRuleAction::from(val.action),
                to: XdpRuleKey {
                    ip: XdpIp([0; 16]),
                    port: 0,
                    eth: network_types::eth::EtherType::Loop,
                    proto: network_types::ip::IpProto::Ipv4,
                },
            },
        }
    }
}

pub trait AsStrExt {
    fn as_str(&self) -> String;
}

pub fn parse_ip(s: String) -> ErrResult<Ip> {
    let ip_str = s.split('/').next().unwrap_or(&s);
    match IpAddr::from_str(ip_str)? {
        IpAddr::V4(ip) => {
            let oct = ip.octets();
            Ok(Ip(u128::from_be_bytes([
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0xff, 0xff,
                oct[0], oct[1], oct[2], oct[3],
            ])))
        }
        IpAddr::V6(ip) => Ok(Ip(u128::from_be_bytes(ip.octets()))),
    }
}

impl AsStrExt for Ip {
    fn as_str(&self) -> String {
        let addr = Ipv6Addr::from(self.0);
        match addr.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => addr.to_string(),
        }
    }
}

pub fn parse_eth(s: String) -> ErrResult<EtherType> {
    match s.to_lowercase().as_str() {
        "ipv4" => Ok(EtherType::Ipv4),
        "ipv6" => Ok(EtherType::Ipv6),
        "arp" => Ok(EtherType::Arp),
        _ => Err(VanguardError::Io("unknown ethertype").into()),
    }
}

impl AsStrExt for EtherType {
    fn as_str(&self) -> String {
        match self {
            Self::Ipv4 => "ipv4".to_string(),
            Self::Ipv6 => "ipv6".to_string(),
            Self::Arp => "arp".to_string(),
            _ => "".to_string(),
        }
    }
}

pub fn parse_proto(s: String) -> ErrResult<IpProto> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(IpProto::Tcp),
        "udp" => Ok(IpProto::Udp),
        "icmp" => Ok(IpProto::Icmp),
        "icmpv6" => Ok(IpProto::Ipv6Icmp),
        "any" => Ok(IpProto::Larp),
        _ => Err(VanguardError::Io("unknown proto").into()),
    }
}

impl AsStrExt for IpProto {
    fn as_str(&self) -> String {
        match self {
            Self::Tcp => "tcp".to_string(),
            Self::Udp => "udp".to_string(),
            Self::Icmp => "icmp".to_string(),
            Self::Ipv6Icmp => "icmpv6".to_string(),
            Self::Larp => "any".to_string(),
            _ => "".to_string(),
        }
    }
}

pub fn parse_action(s: String) -> ErrResult<RuleAction> {
    match s.to_lowercase().as_str() {
        "abort" => Ok(RuleAction::ABORTED),
        "drop" => Ok(RuleAction::DROP),
        "pass" => Ok(RuleAction::PASS),
        "tx" => Ok(RuleAction::TX),
        "redirect" => Ok(RuleAction::REDIRECT),
        _ => Err(VanguardError::Io("unknown action").into()),
    }
}

impl AsStrExt for RuleAction {
    fn as_str(&self) -> String {
        match self {
            Self::ABORTED => "abort".to_string(),
            Self::DROP => "drop".to_string(),
            Self::PASS => "pass".to_string(),
            Self::TX => "tx".to_string(),
            Self::REDIRECT => "redirect".to_string(),
        }
    }
}

pub mod config {
    use super::*;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize_ip<'de, D>(deserializer: D) -> Result<Ip, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_ip(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
    }

    pub fn deserialize_ip_list<'de, D>(deserializer: D) -> Result<Vec<Ip>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let list = Vec::<String>::deserialize(deserializer)?;

        list.iter()
            .map(|s| parse_ip(s.to_string())
                .map_err(|e| SerdeDeError::custom(format!("{e}"))))
            .collect()
    }

    pub fn deserialize_eth<'de, D>(deserializer: D) -> Result<EtherType, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_eth(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
    }

    pub fn deserialize_proto<'de, D>(deserializer: D) -> Result<IpProto, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_proto(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
    }

    pub fn deserialize_action<'de, D>(deserializer: D) -> Result<RuleAction, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(parse_action(s).map_err(|e| SerdeDeError::custom(format!("{e}")))?)
    }
}

pub mod cli {
    use super::*;

    pub fn parse_ip_arg(s: &str) -> std::result::Result<Ip, std::io::Error> {
        parse_ip(s.to_string()).map_err(|e| std::io::Error::other(e.to_string()))
    }

    pub fn parse_eth_arg(s: &str) -> std::result::Result<EtherType, std::io::Error> {
        parse_eth(s.to_string()).map_err(|e| std::io::Error::other(e.to_string()))
    }

    pub fn parse_proto_arg(s: &str) -> std::result::Result<IpProto, std::io::Error> {
        parse_proto(s.to_string()).map_err(|e| std::io::Error::other(e.to_string()))
    }
}