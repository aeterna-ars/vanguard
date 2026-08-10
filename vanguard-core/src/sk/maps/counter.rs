#[repr(C)]
pub struct SkCounter {
    pub last_reset: u64,
    pub count: u32,
}

pub const RESET_INTERVAL: u64 = 1_000_000_000;