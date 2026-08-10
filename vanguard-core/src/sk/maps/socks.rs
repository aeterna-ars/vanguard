use std::os::fd::AsRawFd;

use crate::{common::{commons::*, ip::*}, error::VanguardError};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SockKey {
    pub local_ip: EbpfIp,
    pub remote_ip: EbpfIp,
    pub local_port: u32,
    pub remote_port: u32,
    pub protocol: IpProto,
}

#[cfg(feature = "userspace")]
unsafe impl crate::common::commons::Pod for SockKey {}

pub struct SockMapMap;
impl SockMapMap {
    fn get(bpf: &mut Ebpf) -> Result<SockMap<MapData>, VanguardError> {
        get_map!(bpf, "SOCK_MAP", SockMap, SockMap<MapData>)
    }

    fn add(bpf: &mut Ebpf, index: u32, socket: impl AsRawFd) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;
        map.set(index, &socket, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;
        
        Ok(())
    }
}

pub struct SockHashMap;
impl SockHashMap {
    fn get(bpf: &mut Ebpf) -> Result<SockHash<MapData, SockKey>, VanguardError> {
        get_map!(bpf, "SOCK_HASH", SockHash, SockHash<MapData, SockKey>)
    }

    fn add(bpf: &mut Ebpf, key: SockKey, value: impl AsRawFd) -> Result<(), VanguardError> {
        let mut map = Self::get(bpf)?;
        map.insert(key, value, 0)
            .map_err(|e| VanguardError::EbpfMapError(format!("{e}")))?;

        Ok(())
    }
}