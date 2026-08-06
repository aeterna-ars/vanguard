use crate::common::{ip::*, common::*};

#[cfg(feature = "userspace")]
use erret_result::ErrResult;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SockKey {
    pub local_ip: EbpfIp,
    pub remote_ip: EbpfIp,
    pub local_port: u32,
    pub remote_port: u32,
    pub protocol: IpProto,
}

pub struct SockMapMap;
impl SockMapMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<SockMap<SockKey>> {
        get_map!(bpf, "SOCK_MAP", SockMap, SockMap<SockKey>)
    }

    fn add() -> ErrResult<()> {


        Ok(())
    }
}

pub struct SockHashMap;
impl SockHashMap {
    fn get(bpf: &mut Ebpf) -> ErrResult<SockHash<std::os::fd::RawFd, SockKey>> {
        get_map!(bpf, "SOCK_HASH", SockHash, SockHash<SockKey>)
    }

    fn add() -> ErrResult<()> {
        

        Ok(())
    }
}