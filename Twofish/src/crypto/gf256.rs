pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a_val = a;
    let mut b_val = b;

    const POLYNOMIAL: u8 = 0x69;

    for _ in 0..8 {
        if b_val & 1 != 0 {
            result ^= a_val;
        }

        let high_bit = a_val & 0x80;
        a_val <<= 1;
        if high_bit != 0 {
            a_val ^= POLYNOMIAL;
        }
        b_val >>= 1;
    }

    result
}

pub fn gf_pow(a: u8, exp: usize) -> u8 {
    if exp == 0 {
        return 1;
    }

    if a == 0 {
        return 0;
    }

    let mut result: u8 = 1;
    let mut base = a;
    let mut exponent = exp;

    while exponent > 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }

    result
}
