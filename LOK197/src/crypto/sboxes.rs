pub fn s1(input: u16) -> u8 {
    let preprocessed = (input as u32) ^ 0x1FFF;
    let squared = multiply_polynomials(preprocessed, preprocessed);
    let cubed = multiply_polynomials(squared, preprocessed);
    (modular_reduce(cubed, 0x2911, 13) & 0xFF) as u8
}

pub fn s2(input: u16) -> u8 {
    let preprocessed = (input as u32) ^ 0x07FF;
    let squared = multiply_polynomials(preprocessed, preprocessed);
    let cubed = multiply_polynomials(squared, preprocessed);
    (modular_reduce(cubed, 0x0AA7, 11) & 0xFF) as u8
}

pub fn multiply_polynomials(mut left: u32, mut right: u32) -> u32 {
    let mut result = 0;
    while right != 0 {
        if (right & 1) != 0 {
            result ^= left;
        }
        left <<= 1;
        right >>= 1;
    }
    result
}

pub fn modular_reduce(mut value: u32, modulus: u32, degree: u8) -> u32 {
    let degree = degree as usize;
    while let Some(highest_bit) = (degree..32).rev().find(|&bit| (value & (1 << bit)) != 0) {
        value ^= modulus << (highest_bit - degree);
    }
    value
}