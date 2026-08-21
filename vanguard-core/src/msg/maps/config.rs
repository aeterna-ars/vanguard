#[cfg(feature = "userspace")]
use super::*;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct MsgConfig {
    pub block_time: u64,
    pub rate_limit: u32,
    pub block_on_excess: bool,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for MsgConfig {}

#[cfg(feature = "userspace")]
pub struct MsgConfigMap;

#[cfg(feature = "userspace")]
impl MsgConfigMap {
    pub fn get(bpf: &mut Ebpf) -> Result<Array<MapData, MsgConfig>, VanguardError> {
        get_map!(bpf, "CONFIG", Array, Array<MapData, MsgConfig>)
    }

    pub fn read(bpf: &mut Ebpf) -> Result<MsgConfig, VanguardError> {
        let map = Self::get(bpf)?;
        let mp = map.get(&0, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(mp)
    }

    pub fn write(bpf: &mut Ebpf, config: MsgConfig) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;
        map.set(0, config, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}