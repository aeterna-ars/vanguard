#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XdpIp(pub [u8; 16]);
impl XdpIp {
    pub fn from_v4(v4: [u8; 4]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[10] = 0xFF;
        bytes[11] = 0xFF;
        bytes[12] = v4[0];
        bytes[13] = v4[1];
        bytes[14] = v4[2];
        bytes[15] = v4[3];
        Self(bytes)
    }

    pub fn from_v6(v6: [u8; 16]) -> Self {
        Self(v6)
    }
}