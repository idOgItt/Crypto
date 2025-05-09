use rsa::primality::{SolovayStrassenTest, PrimalityTest};
use num_bigint::BigUint;
use num_traits::FromPrimitive;

#[test]
fn test_solovay_strassen_on_primes() {
    let test = SolovayStrassenTest;
    let primes = [3u32, 5, 7, 13, 23, 29];

    for &p in &primes {
        let n = BigUint::from_u32(p).unwrap();
        assert!(test.is_probably_prime(&n, 0.99), "SS failed on prime {}", p);
    }
}

#[test]
fn test_solovay_strassen_on_composites() {
    let test = SolovayStrassenTest;
    let composites = [9u32, 15, 21, 27, 33];

    for &n in &composites {
        let n = BigUint::from_u32(n).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "SS failed on composite {}", n);
    }
}

#[test]
fn test_solovay_strassen_small_n() {
    let test = SolovayStrassenTest;
    let small_values = [0u32, 1, 2];

    for &v in &small_values {
        let n = BigUint::from_u32(v).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "SS incorrectly passed n = {}", v);
    }
}

#[test]
fn test_solovay_strassen_rejects_carmichael() {
    let test = SolovayStrassenTest;
    let carmichaels = [561u32, 1105, 1729, 2465, 2821];

    for &n in &carmichaels {
        let n = BigUint::from_u32(n).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "SS accepted Carmichael number {}", n);
    }
}

#[test]
fn test_solovay_strassen_on_large_cases() {
    let test = SolovayStrassenTest;

    let prime = BigUint::parse_bytes(b"32416190071", 10).unwrap(); // простое
    let composite = &prime * 5u32;

    assert!(test.is_probably_prime(&prime, 0.99), "SS failed on large prime");
    assert!(!test.is_probably_prime(&composite, 0.99), "SS failed on large composite");
}

use quickcheck::quickcheck;
use rand::thread_rng;
use num_bigint::RandBigInt;

quickcheck! {
    fn prop_solovay_rejects_odd_composites(a: u8, b: u8) -> bool {
        if a < 3 || b < 3 { return true; }
        let n = (a as u32) * (b as u32);
        if n % 2 == 0 || n < 9 || a == b { return true; }
        let n = BigUint::from(n);
        let test = SolovayStrassenTest;
        !test.is_probably_prime(&n, 0.99)
    }
}
