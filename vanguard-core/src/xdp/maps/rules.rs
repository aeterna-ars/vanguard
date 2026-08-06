#[cfg(feature = "userspace")]
use crate::common::{common::*, ip::*};

use network_types::{
    eth::EtherType,
    ip::IpProto,
};

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[cfg(feature = "userspace")]
use crate::xdp::error::*;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct XdpRuleKey {
    pub ip: EbpfIp,
    pub port: u16,
    pub eth: EtherType,
    pub proto: IpProto,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpRuleKey {}

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct XdpRuleValue {
    pub redirect: XdpRuleKey,
    pub action: XdpRuleAction,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpRuleValue {}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum XdpRuleAction {
    ABORTED = 0,
    DROP = 1,
    PASS = 2,
    TX = 3,
    REDIRECT = 4,
}

#[cfg(feature = "userspace")]
impl Parse for XdpRuleAction {
    fn as_str(&self) -> String {
        match self {
            Self::ABORTED => "abort".to_string(),
            Self::DROP => "drop".to_string(),
            Self::PASS => "pass".to_string(),
            Self::TX => "tx".to_string(),
            Self::REDIRECT => "redirect".to_string(),
        }
    }

    fn to_type(s: String) -> ErrResult<Self> {
        match s.to_lowercase().trim() {
            "abort" => Ok(Self::ABORTED),
            "drop" => Ok(Self::DROP),
            "pass" => Ok(Self::PASS),
            "tx" => Ok(Self::TX),
            "redirect" => Ok(Self::REDIRECT),
            _ => Err(VanguardError::Io("unknown action").into())
        }
    }
}

#[cfg(feature = "userspace")]
pub struct RulesMap;

#[cfg(feature = "userspace")]
impl RulesMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<HashMap<MapData, XdpRuleKey, XdpRuleValue>> {
        get_map!(bpf, "RULES", HashMap, HashMap<MapData, XdpRuleKey, XdpRuleValue>)
    }

    pub fn add(bpf: &mut Ebpf, key: XdpRuleKey, value: XdpRuleValue) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        let key = XdpRuleKey::from(key);
        let value = XdpRuleValue::from(value);

        map.insert(&key, value, 0)?;
        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, key: XdpRuleKey) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        let key = XdpRuleKey::from(key);

        map.remove(&key)?;
        Ok(())
    }
}