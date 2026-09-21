#[cfg(feature = "userspace")]
use super::*;
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct BlockEvent {
    pub ip: EbpfIp,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for BlockEvent {}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct AccessValue {
    pub is_blocked: bool,
    pub until: u32,
}
#[cfg(feature = "userspace")]
unsafe impl Pod for AccessValue {}

#[cfg(feature = "userspace")]
pub struct AccessListMap {
    map: LpmTrie<MapData, EbpfIp, AccessValue>,
}

#[cfg(feature = "userspace")]
impl AccessListMap {
    pub fn get(bpf: &mut Ebpf) -> Result<Self, VanguardError> {
        let map = get_map!(bpf, "ACCESSLIST", LpmTrie, LpmTrie<MapData, EbpfIp, AccessValue>)?;
        Ok(Self { map })
    }

    pub fn get_val(&self, key: &Key<EbpfIp>) -> Result<AccessValue, VanguardError> {
        self.map.get(&key, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))
    }

    pub fn has_key(&self, key: &Key<EbpfIp>) -> bool {
        self.get_val(key).is_ok()
    }

    pub fn block(&mut self, ip: EbpfNet, until: u32) -> Result<(), VanguardError> {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);

        if self.has_key(&key) {
            return Ok(());
        }

        let value = AccessValue { is_blocked: false, until };
        self.map.insert(&key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }

    pub fn white(&mut self, ip: EbpfNet, until: u32) -> Result<(), VanguardError> {
        let key: Key<EbpfIp> = Key::new(ip.prefix_len, ip.ip);

        if self.has_key(&key) {
            return Ok(());
        }

        let value = AccessValue { 
            is_blocked: true,
            until, 
        };

        self.map
            .insert(&key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("Map insert error: {e}")))?;

        Ok(())
    }

    pub fn remove(&mut self, ip: EbpfNet) -> Result<(), VanguardError> {
        let key = Key::new(ip.prefix_len, ip.ip);
        
        if !self.has_key(&key) {
            return Ok(());
        }

        self.map
            .remove(&key)
            .map_err(|e| VanguardError::EbpfMapError(format!("Map remove error: {e}")))?;

        Ok(())
    }
}