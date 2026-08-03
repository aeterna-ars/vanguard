#[cfg(feature = "userspace")]
use super::common::*;

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct XdpConfig {
    pub block_time: u64,
    pub rate_limit: u32,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpConfig {}

#[cfg(feature = "userspace")]
pub struct ConfigMap;

#[cfg(feature = "userspace")]
impl ConfigMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<Array<MapData, XdpConfig>> {
        get_map!(bpf, "CONFIG", Array, Array<MapData, XdpConfig>)
    }

    pub fn read(bpf: &mut Ebpf) -> ErrResult<XdpConfig> {
        let map = Self::get(bpf)?;
        let mp = map.get(&0, 0)?;
        let mp = XdpConfig::from(mp);
        Ok(mp)
    }

    pub fn write(bpf: &mut Ebpf, config: XdpConfig) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        let config = XdpConfig::from(config);

        map.set(0, config, 0)?;

        Ok(())
    }
}