#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsgPacketCounter {
    pub tokens: u64,
    pub last_update: u64,
}