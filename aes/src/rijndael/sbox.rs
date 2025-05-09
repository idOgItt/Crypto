use crate::gf::arithmetic::{poly_inv, Poly};

/// Преобразует байт `x` в S-box значение (через gf_inv + аффинное преобразование)
pub fn sbox(x: u8, poly: &Poly) -> u8 {
    todo!("x → inv(x) в GF(2⁸) → аффинное преобразование")
}

/// Преобразует байт `x` в Inv-S-box значение (обратное аффинное + inv)
pub fn inv_sbox(x: u8, poly: &Poly) -> u8 {
    todo!("x → обратное аффинное → inv(x)")
}
