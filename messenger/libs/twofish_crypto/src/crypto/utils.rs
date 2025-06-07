pub fn rotate_left(x: u32, r: u8) -> u32 {
    let r = (r as u32) % 32;
    let inv = (32 - r) % 32;
    (x << r) | (x >> inv)
}

pub fn rotate_right(x: u32, r: u8) -> u32 {
    let r = (r as u32) % 32;
    let inv = (32 - r) % 32;
    (x >> r) | (x << inv)
}
