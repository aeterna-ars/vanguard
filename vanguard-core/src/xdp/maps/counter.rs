#[repr(C)]
pub struct XdpCounter {
    pub last_reset: u64,
    pub count: u32,
}

pub const RESET_INTERVAL: u64 = 1_000_000_000;