use crate::gf::arithmetic::{poly_inv, Poly};

fn byte_to_poly(x: u8) -> Poly {
    let mut v = Vec::with_capacity(9);
    for i in 0..8 {
        v.push((x >> i) & 1 != 0);
    }
    v.push(false);
    v
}

fn poly_to_byte(p: &Poly) -> u8 {
    p.iter()
        .take(8)
        .enumerate()
        .fold(0u8, |acc, (i, &b)| if b { acc | (1 << i) } else { acc })
}

/// AES S-box: x → x⁻¹ в GF(2⁸) → аффинное преобразование
pub fn sbox(x: u8, poly: &Poly) -> u8 {
    let inv = if x == 0 {
        0
    } else {
        let p = byte_to_poly(x);
        let ip = poly_inv(&p, poly);
        poly_to_byte(&ip)
    };
    
    let mut result = 0u8;

    for i in 0..8 {
        let b_i = (inv >> i) & 1;
        let b_i4 = (inv >> ((i + 4) % 8)) & 1;
        let b_i5 = (inv >> ((i + 5) % 8)) & 1;
        let b_i6 = (inv >> ((i + 6) % 8)) & 1;
        let b_i7 = (inv >> ((i + 7) % 8)) & 1;

        let c_i = (0x63 >> i) & 1;

        let new_bit = b_i ^ b_i4 ^ b_i5 ^ b_i6 ^ b_i7 ^ c_i;

        result |= new_bit << i;
    }

    result
}

/// AES Inv-S-box: обратное аффинное → x⁻¹
pub fn inv_sbox(x: u8, poly: &Poly) -> u8 {


    let mut u = 0u8;

    for i in 0..8 {
        let b_i2 = (x >> ((i + 2) % 8)) & 1;
        let b_i5 = (x >> ((i + 5) % 8)) & 1;
        let b_i7 = (x >> ((i + 7) % 8)) & 1;

        let d_i = (0x05 >> i) & 1;

        let new_bit = b_i2 ^ b_i5 ^ b_i7 ^ d_i;

        u |= new_bit << i;
    }

    if u == 0 {
        0
    } else {
        let p = byte_to_poly(u);
        let ip = poly_inv(&p, poly);
        poly_to_byte(&ip)
    }
}