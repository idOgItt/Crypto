use rijndael::gf::arithmetic::{poly_add, poly_divmod, poly_inv, poly_mod, poly_mul, poly_mulmod, poly_powmod, Poly};

fn poly_from_bits(bits: &[u8]) -> Poly {
    // вспомогательная функция: bits[i]==1 → coefficient true
    bits.iter().map(|&b| b != 0).collect()
}

fn bits_from_poly(p: &Poly) -> Vec<u8> {
    p.iter().map(|&b| if b { 1 } else { 0 }).collect()
}

#[test]
fn test_poly_add_same_length() {
    // (1 + x^2) + (1 + x) = x^2 + x
    let a = poly_from_bits(&[1,0,1]);
    let b = poly_from_bits(&[1,1,0]);
    let c = poly_add(&a, &b);
    assert_eq!(bits_from_poly(&c), vec![0,1,1]);
}

#[test]
fn test_poly_add_diff_length() {
    // x^3 + 1 + (x + 1) = x^3 + x
    let a = poly_from_bits(&[1,0,0,1]);
    let b = poly_from_bits(&[1,1]);
    let c = poly_add(&a, &b);
    assert_eq!(bits_from_poly(&c), vec![0,1,0,1]);
}

#[test]
fn test_poly_add_zero() {
    let a = poly_from_bits(&[1,0,1,1]);
    let zero: Poly = vec![];
    let c = poly_add(&a, &zero);
    assert_eq!(bits_from_poly(&c), bits_from_poly(&a));
}

#[test]
fn test_poly_mul_simple() {
    // (x + 1)*(x^2 + 1) = x^3 + x^2 + x + 1
    let a = poly_from_bits(&[1,1]);
    let b = poly_from_bits(&[1,0,1]);
    let p = poly_mul(&a, &b);
    assert_eq!(bits_from_poly(&p), vec![1,1,1,1]);
}

#[test]
fn test_poly_mul_by_zero() {
    let a = poly_from_bits(&[1,1,1]);
    let zero: Poly = vec![];
    let p = poly_mul(&a, &zero);
    assert_eq!(p.len(), 0);
}

#[test]
fn test_poly_mul_by_one() {
    let one = poly_from_bits(&[1]);
    let a = poly_from_bits(&[0,1,1,0]);
    let p = poly_mul(&a, &one);
    assert_eq!(bits_from_poly(&p), bits_from_poly(&a));
}

#[test]
fn test_poly_mul_degree_sum() {
    // degrees add: deg(a)=2, deg(b)=3 → deg=5
    let a = poly_from_bits(&[1,0,1]);        // x^2 + 1
    let b = poly_from_bits(&[0,1,0,1]);      // x^3 + x
    let p = poly_mul(&a, &b);
    assert_eq!(p.len(), 6);
    assert_eq!(bits_from_poly(&p), vec![0,1,0,1,0,1]);
}

#[test]
fn test_poly_divmod_exact() {
    // (x^2 + 1) / (x + 1) = (x + 1), rem = 0
    let dividend = poly_from_bits(&[1,0,1]);
    let divisor  = poly_from_bits(&[1,1]);
    let (q, r) = poly_divmod(&dividend, &divisor);
    assert_eq!(bits_from_poly(&q), vec![1,1]);
    assert!(r.is_empty());
}

#[test]
fn test_poly_divmod_with_remainder() {
    // (x^3 + x) / (x^2 + 1) = x, rem = x
    let dividend = poly_from_bits(&[0,1,0,1]);
    let divisor  = poly_from_bits(&[1,0,1]);
    let (q, r) = poly_divmod(&dividend, &divisor);
    assert_eq!(bits_from_poly(&q), vec![0,1]); // x
    assert_eq!(bits_from_poly(&r), vec![0,1]); // x
}

#[test]
fn test_poly_mod() {
    let a = poly_from_bits(&[1,0,0,1,1]);  // x^4 + x + 1
    let m = poly_from_bits(&[1,0,1]);      // x^2 + 1
    let r = poly_mod(&a, &m);
    // (x^4 + x +1) mod (x^2+1) = x + 0
    assert_eq!(bits_from_poly(&r), vec![0,1]);
}

#[test]
fn test_poly_mulmod() {
    let a = poly_from_bits(&[1,1]);        // x+1
    let b = poly_from_bits(&[1,1,1]);      // x^2+x+1
    let m = poly_from_bits(&[1,0,1]);      // x^2+1
    // (x+1)*(x^2+x+1)= x^3+? = poly_mul gives [1,0,1,1], mod (x^2+1)=?
    let r = poly_mulmod(&a, &b, &m);
    // direct: p=[1,1,1,1]→mod divisor→rem=[0,1]
    assert_eq!(bits_from_poly(&r), vec![0,1]);
}

#[test]
fn test_poly_powmod_zero_exp() {
    let a = poly_from_bits(&[1,0,1]);
    let m = poly_from_bits(&[1,0,1,1]); // x^3+x+1
    let r = poly_powmod(&a, 0, &m);
    assert_eq!(bits_from_poly(&r), vec![1]); // 1
}

#[test]
fn test_poly_powmod() {
    // a=x (=[0,1]), exp=3: x^3 mod (x^2+1) = x^3 mod (x^2+1) = x+0
    let a = poly_from_bits(&[0,1]);
    let m = poly_from_bits(&[1,0,1]); // x^2+1
    let r = poly_powmod(&a, 3, &m);
    assert_eq!(bits_from_poly(&r), vec![0,1]);
}

#[test]
fn test_poly_inv() {
    // In GF(2)[x]/(x^3+x+1): check inv of x = x^2
    let a = poly_from_bits(&[0,1]);       // x
    let m = poly_from_bits(&[1,0,1,1]);   // x^3+x+1
    let inv = poly_inv(&a, &m);
    // verify a*inv mod m == 1
    let prod = poly_mulmod(&a, &inv, &m);
    assert_eq!(bits_from_poly(&prod), vec![1]);
}
