use super::common::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpRuleKey {
    pub ip: XdpIp,
    pub port: u16,
    pub eth: EtherType,
    pub proto: IpProto,
}
unsafe impl Pod for XdpRuleKey {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpRuleValue {
    pub action: XdpRuleAction,
    pub to: XdpRuleKey,
}
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

    pub fn add(bpf: &mut Ebpf, key: RuleKey, value: RuleValue) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        let key = XdpRuleKey::from(key);
        let value = XdpRuleValue::from(value);

        map.insert(&key, value, 0)?;
        Ok(())
    }

    pub fn remove(bpf: &mut Ebpf, key: RuleKey) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        let key = XdpRuleKey::from(key);

        map.remove(&key)?;
        Ok(())
    }
}