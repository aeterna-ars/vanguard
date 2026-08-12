#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpPacketCounter {
    pub tokens: u64,
    pub last_update: u64,
}