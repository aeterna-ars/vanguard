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
pub struct XdpConf {
    #[serde(deserialize_with = "deserialize_config")]
    pub config: XdpConfig,
    
    #[serde(default)]
    pub rules: Rule,
}

impl XdpConf {
    pub fn load(path: &str) -> ErrResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: XdpConf = serde_yaml::from_str(&content)?;
        Ok(cfg)
    }
}

#[derive(Deserialize)]
pub struct Rule {
    #[serde(deserialize_with = "deserialize_rkey")]
    pub key: XdpRuleKey,

    #[serde(deserialize_with = "deserialize_rval")]
    pub value: XdpRuleValue,
}

mod serialize {
    use vanguard_core::network_types::{
        eth::EtherType,
        ip::IpProto,
    };
    use vanguard_core::common::{commons::*};
    use super::*;
    use serde::{Deserialize, Deserializer, de::Error};

    #[derive(Debug, Clone, Deserialize)]
    pub struct XdpConfigWrapper {
        pub rate_limit: u32,
        pub burst_limit: u32,
    }

    impl TryFrom<XdpConfigWrapper> for XdpConfig {
        type Error = ErrRet;

        fn try_from(wrapper: XdpConfigWrapper) -> Result<Self, Self::Error> {
            Ok(XdpConfig::new(wrapper.rate_limit, wrapper.burst_limit))
        }
    }

    pub fn deserialize_config<'de, D>(deserializer: D) -> Result<XdpConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapper: XdpConfigWrapper = Deserialize::deserialize(deserializer)?;
        let ret: XdpConfig = wrapper.try_into().map_err(|e| D::Error::custom(format!("{e}")))?;
        Ok(ret)
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
                ip: EbpfIp::to_type(w.ip)?,
                port: EbpfPort(w.port),
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
        let ret: XdpRuleKey = wrapper.try_into().map_err(|e| D::Error::custom(format!("{e}")))?;
        Ok(ret)
    }

    #[derive(Clone, Deserialize)]
    pub struct XdpRuleValueWrapper {
        pub action: String,
        pub redirect: Option<XdpRuleKeyWrapper>,
    }

    impl TryFrom<XdpRuleValueWrapper> for XdpRuleValue {
        type Error = ErrRet;

        fn try_from(w: XdpRuleValueWrapper) -> Result<Self, Self::Error> {
            let redirect_key: XdpRuleKey = if let Some(re) = w.redirect {
                re.try_into()?
            } else {
                unsafe { core::mem::zeroed() }
            };
            
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
        let ret: XdpRuleValue = wrapper.try_into().map_err(|e| D::Error::custom(format!("{e}")))?;
        Ok(ret)
    }

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