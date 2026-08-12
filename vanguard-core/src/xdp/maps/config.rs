#[cfg(feature = "userspace")]
use super::*;

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
    fn get(bpf: &mut Ebpf) -> Result<Array<MapData, XdpConfig>, VanguardError> {
        get_map!(bpf, "CONFIG", Array, Array<MapData, XdpConfig>)
    }

    pub fn read(bpf: &mut Ebpf) -> Result<XdpConfig, VanguardError> {
        let map = Self::get(bpf)?;
        let mp = map.get(&0, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(mp)
    }

    pub fn write(bpf: &mut Ebpf, config: XdpConfig) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;
        map.set(0, config, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}