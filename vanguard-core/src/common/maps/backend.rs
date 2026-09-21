#[cfg(feature = "userspace")]
use super::*;

#[repr(C)]
pub struct BackendMap {
    map: Array<MapData, EbpfIp>,
}

#[cfg(feature = "userspace")]
impl BackendMap {
    pub fn get(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "BACKEND_ARRAY", Array, Array<MapData, EbpfIp>)?;
        Ok(Self { map })
    }

    pub fn set(&mut self, idx: u32, val: EbpfIp) -> Result<(), VanguardError> {
        self.map.set(idx, val, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))
    }
}

pub struct Balancing {
    
}