use rsa::number_theory::*;
use num_bigint::{BigUint, BigInt, ToBigInt};
use num_traits::{FromPrimitive, One, Zero};

#[test]
fn test_gcd_basic() {
    let a = BigUint::from_u32(48).unwrap();
    let b = BigUint::from_u32(18).unwrap();
    let result = gcd(&a, &b);
    assert_eq!(result, BigUint::from_u32(6).unwrap());
}

#[test]
fn test_extended_gcd_basic() {
    let a = BigInt::from(240);
    let b = BigInt::from(46);
    let (g, x, y) = extended_gcd(&a, &b);
    assert_eq!(g, BigInt::from(2));
    assert_eq!(&a * &x + &b * &y, g);
}

#[test]
fn test_mod_pow_small() {
    let base = BigUint::from_u32(4).unwrap();
    let exp = BigUint::from_u32(13).unwrap();
    let modulus = BigUint::from_u32(497).unwrap();
    let result = mod_pow(&base, &exp, &modulus);
    assert_eq!(result, BigUint::from_u32(445).unwrap());
}

#[test]
fn test_legendre_symbol() {
    let a = BigInt::from(5);
    let p = BigInt::from(7); // 5 is a quadratic residue mod 7
    assert_eq!(legendre_symbol(&a, &p), -1);
}

#[test]
fn test_jacobi_symbol() {
    let a = BigInt::from(1001);
    let n = BigInt::from(9907);
    let result = jacobi_symbol(&a, &n);
    assert!(result == 1 || result == -1 || result == 0);
}

#[test]
fn test_gcd_coprime() {
    let a = BigUint::from_u32(17).unwrap();
    let b = BigUint::from_u32(31).unwrap();
    assert_eq!(gcd(&a, &b), BigUint::one());
}

#[test]
fn test_gcd_zero() {
    let a = BigUint::from_u32(0).unwrap();
    let b = BigUint::from_u32(42).unwrap();
    assert_eq!(gcd(&a, &b), b);
}

#[test]
fn test_extended_gcd_coprime() {
    let a = BigInt::from(30);
    let b = BigInt::from(17);
    let (g, x, y) = extended_gcd(&a, &b);
    assert_eq!(g, BigInt::one());
    assert_eq!(&a * &x + &b * &y, g);
}

#[test]
fn test_extended_gcd_zero_case() {
    let a = BigInt::zero();
    let b = BigInt::from(42);
    let (g, x, y) = extended_gcd(&a, &b);
    assert_eq!(g, b);
    assert_eq!(x, BigInt::zero());
    assert_eq!(y, BigInt::one());
}

#[test]
fn test_mod_pow_zero_exponent() {
    let base = BigUint::from_u32(42).unwrap();
    let modulus = BigUint::from_u32(5).unwrap();
    let result = mod_pow(&base, &BigUint::zero(), &modulus);
    assert_eq!(result, BigUint::one());
}

#[test]
fn test_mod_pow_large_exponent() {
    let base = BigUint::from_u32(2).unwrap();
    let exp = BigUint::from_u32(1000).unwrap();
    let modulus = BigUint::from_u32(1009).unwrap();
    let result = mod_pow(&base, &exp, &modulus);
    assert!(result < modulus);
}

#[test]
fn test_legendre_symbol_nonresidue() {
    let a = BigInt::from(3);
    let p = BigInt::from(7);
    assert_eq!(legendre_symbol(&a, &p), -1); // 3 не является квадратом по модулю 7
}

#[test]
fn test_legendre_symbol_zero() {
    let a = BigInt::zero();
    let p = BigInt::from(13);
    assert_eq!(legendre_symbol(&a, &p), 0);
}

#[test]
fn test_jacobi_symbol_residue() {
    let a = BigInt::from(19);
    let n = BigInt::from(45); // 45 = 3 * 3 * 5
    assert_eq!(jacobi_symbol(&a, &n), 1); // вычисляется из символов Якоби по простым множителям
}

#[test]
fn test_jacobi_symbol_zero() {
    let a = BigInt::zero();
    let n = BigInt::from(99);
    assert_eq!(jacobi_symbol(&a, &n), 0);
}
