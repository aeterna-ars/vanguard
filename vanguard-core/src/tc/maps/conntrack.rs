#[cfg(feature = "userspace")]
use super::*;

#[derive(Clone, Copy)]
pub struct Index { pub idx: u16 }
#[cfg(feature = "userspace")]
unsafe impl Pod for Index {}

#[cfg(feature = "userspace")]
pub struct ConnMap {
    map: HashMap<MapData, Tuple5, Index>,
}

#[cfg(feature = "userspace")]
impl ConnMap {
    pub fn get(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "CONNTRACK", LruHashMap, HashMap<MapData, Tuple5, Index>)?;
        Ok(Self { map })
    }
}