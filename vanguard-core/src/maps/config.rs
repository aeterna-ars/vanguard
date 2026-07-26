use super::common::*;
use erret_result::ErrResult;

#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(feature = "userspace", derive(clap::Args, serde::Serialize, serde::Deserialize))]
pub struct XdpConfig {
    pub rate_limit: u32,
    pub block_time: u64,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpConfig {}

pub struct ConfigMap;
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