#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpCounter {
    pub count: u32,
    pub last_reset: u64,
}