use super::common::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpConfig {
    pub rate_limit: u32,
    pub block_time: u64,
}
unsafe impl Pod for XdpConfig {}

pub struct ConfigMap;
impl ConfigMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<Array<MapData, XdpConfig>> {
        get_map!(bpf, "CONFIG", Array, Array<MapData, XdpConfig>)
    }

    pub fn read(bpf: &mut Ebpf) -> ErrResult<Config> {
        let map = Self::get(bpf)?;
        let mp = map.get(&0, 0)?;
        let mp = Config::from(mp);
        Ok(mp)
    }

    pub fn write(bpf: &mut Ebpf, config: Config) -> ErrResult<()> {
        let mut map = Self::get(bpf)?;

        let config = XdpConfig::from(config);

        map.set(0, config, 0)?;

        Ok(())
    }
}