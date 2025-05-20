use LOK197::crypto::sboxes::{multiply_polynomials, modular_reduce, s1, s2};

fn s1_expected(x: u16) -> u8 {
    let v  = (x as u32) ^ 0x1FFF;
    let v2 = multiply_polynomials(v, v);
    let v3 = multiply_polynomials(v2, v);
    (modular_reduce(v3, 0x2911, 13) & 0xFF) as u8
}

fn s2_expected(x: u16) -> u8 {
    let v  = (x as u32) ^ 0x07FF;
    let v2 = multiply_polynomials(v, v);
    let v3 = multiply_polynomials(v2, v);
    (modular_reduce(v3, 0x0AA7, 11) & 0xFF) as u8
}

#[test]
fn test_s1_against_expected() {
    for &x in &[0x0000, 0x0001, 0x1000, 0x1FFF] {
        assert_eq!(s1(x), s1_expected(x));
    }
}

#[test]
fn test_s2_against_expected() {
    for &x in &[0x0000, 0x0001, 0x0700, 0x07FF] {
        assert_eq!(s2(x), s2_expected(x));
    }
}
