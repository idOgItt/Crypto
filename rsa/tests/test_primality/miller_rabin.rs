use rsa::primality::{MillerRabinTest, PrimalityTest};
use num_bigint::BigUint;
use num_traits::FromPrimitive;

#[test]
fn test_miller_rabin_on_primes() {
    let test = MillerRabinTest;
    let primes = [5u32, 7, 17, 31, 61];

    for &p in &primes {
        let n = BigUint::from_u32(p).unwrap();
        assert!(test.is_probably_prime(&n, 0.99), "MR failed on prime {}", p);
    }
}

#[test]
fn test_miller_rabin_on_composites() {
    let test = MillerRabinTest;
    let composites = [9u32, 15, 25, 27, 35];

    for &n in &composites {
        let n = BigUint::from_u32(n).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "MR failed on composite {}", n);
    }
}

#[test]
fn test_miller_rabin_rejects_carmichael() {
    let test = MillerRabinTest;
    let carmichaels = [561u32, 1105, 1729, 2465, 2821, 6601];

    for &n in &carmichaels {
        let n = BigUint::from_u32(n).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "MR accepted Carmichael number {}", n);
    }
}

#[test]
fn test_miller_rabin_on_small_n() {
    let test = MillerRabinTest;
    let values = [0u32, 1, 2];

    for &v in &values {
        let n = BigUint::from_u32(v).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "MR incorrectly passed n = {}", v);
    }
}

#[test]
fn test_miller_rabin_large_cases() {
    let test = MillerRabinTest;

    let prime = BigUint::parse_bytes(b"32416190071", 10).unwrap(); // простое
    let composite = &prime * 11u32;

    assert!(test.is_probably_prime(&prime, 0.99), "MR failed on large prime");
    assert!(!test.is_probably_prime(&composite, 0.99), "MR failed on large composite");
}

use quickcheck::quickcheck;
use rand::thread_rng;
use num_bigint::RandBigInt;

quickcheck! {
    fn prop_miller_rabin_rejects_odd_composites(a: u8, b: u8) -> bool {
        if a < 3 || b < 3 { return true; }
        let n = (a as u32) * (b as u32);
        if n % 2 == 0 || n < 9 || a == b { return true; } // исключаем чётные, тривиальные, квадраты
        let n = BigUint::from(n);
        let test = MillerRabinTest;
        !test.is_probably_prime(&n, 0.99)
    }
}
