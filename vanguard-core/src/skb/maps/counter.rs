#[repr(C)]
#[derive(Clone, Copy)]
pub struct SkPacketCounter {
    pub tokens: u64,
    pub last_update: u64,
}