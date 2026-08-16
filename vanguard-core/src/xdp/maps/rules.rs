#[cfg(feature = "userspace")]
use super::*;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct XdpRuleKey {
    pub ip: EbpfIp,
    pub port: EbpfPort,
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
    fn as_str(&self) -> Result<String, VanguardError> {
        match self {
            Self::ABORTED => Ok("abort".to_string()),
            Self::DROP => Ok("drop".to_string()),
            Self::PASS => Ok("pass".to_string()),
            Self::TX => Ok("tx".to_string()),
            Self::REDIRECT => Ok("redirect".to_string()),
        }
    }

    fn to_type(s: String) -> Result<Self, VanguardError> {
        match s.to_lowercase().trim() {
            "abort" => Ok(Self::ABORTED),
            "drop" => Ok(Self::DROP),
            "pass" => Ok(Self::PASS),
            "tx" => Ok(Self::TX),
            "redirect" => Ok(Self::REDIRECT),
            _ => Err(VanguardError::IoError("unknown action"))
        }
    }
}

#[cfg(feature = "userspace")]
pub struct RulesMap;

#[cfg(feature = "userspace")]
impl RulesMap {
    pub fn get(bpf: &mut Ebpf) -> Result<HashMap<MapData, XdpRuleKey, XdpRuleValue>, VanguardError> {
        get_map!(bpf, "RULES", HashMap, HashMap<MapData, XdpRuleKey, XdpRuleValue>)
    }

    pub fn add(bpf: &mut Ebpf, key: XdpRuleKey, value: XdpRuleValue) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.insert(key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, key: XdpRuleKey) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;

        map.remove(&key)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}