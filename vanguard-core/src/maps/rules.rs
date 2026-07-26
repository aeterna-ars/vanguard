use super::common::*;
use erret_result::ErrResult;
use super::{
    ip::XdpIp,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpRuleKey {
    pub ip: XdpIp,
    pub port: u16,
    pub eth: EtherType,
    pub proto: IpProto,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpRuleKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpRuleValue {
    pub action: XdpRuleAction,
    pub redirect: XdpRuleKey,
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

pub struct RulesMap;
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