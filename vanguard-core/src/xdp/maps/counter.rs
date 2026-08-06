#[repr(C)]
pub struct XdpCounter {
    pub last_reset: u64,
    pub count: u32,
}