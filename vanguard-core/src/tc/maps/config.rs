#[cfg(feature = "userspace")]
use super::*;

#[repr(C)]
#[cfg_attr(feature = "userspace", derive(Clone, Copy))]
pub struct XdpConfig {
    pub rate_limit: u32,
    pub interval: u64,
    pub max_tokens: u64,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for XdpConfig {}
#[cfg(feature = "userspace")]
impl XdpConfig {
    pub fn new(rate_limit: u32, burst_limit: u32) -> Self {
        let interval = if rate_limit > 0 {
            1_000_000_000u64 / (rate_limit as u64) / 4
        } else {
            u64::MAX
        };

        Self {
            rate_limit: rate_limit / 4,

            interval,
            max_tokens: burst_limit as u64,
        }
    }
}

#[cfg(feature = "userspace")]
pub struct XdpConfigMap;

#[cfg(feature = "userspace")]
impl XdpConfigMap {
    pub fn get(bpf: &mut Ebpf) -> Result<Array<MapData, XdpConfig>, VanguardError> {
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