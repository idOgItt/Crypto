use rsa::primality::{FermatTest, PrimalityTest};
use num_bigint::BigUint;
use num_traits::FromPrimitive;

#[cfg(test)]
extern crate quickcheck;

#[test]
fn test_fermat_on_small_primes() {
    let test = FermatTest;
    let primes = [3u32, 5, 7, 11, 17, 19];

    for &p in &primes {
        let n = BigUint::from_u32(p).unwrap();
        assert!(test.is_probably_prime(&n, 0.99), "Fermat failed on prime {}", p);
    }
}

#[test]
fn test_fermat_on_composites() {
    let test = FermatTest;
    let composites = [4u32, 6, 8, 9, 15, 21, 25];

    for &n in &composites {
        let n = BigUint::from_u32(n).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "Fermat failed on composite {}", n);
    }
}

#[test]
fn test_fermat_may_fail_on_carmichael_numbers() {
    let test = FermatTest;
    let carmichaels = [561u32, 1105, 1729, 2465, 2821, 6601];
    let mut any_failed = false;

    for i in 0..10 {
        for &n in &carmichaels {
            let n = BigUint::from_u32(n).unwrap();
            if test.is_probably_prime(&n, 0.99) {
                any_failed = true;
                break;
            }
        }
    }

    assert!(any_failed, "FermatTest ни разу не ошибся на Кармайкловых числах, хотя должен был хотя бы раз");
}


#[test]
fn test_fermat_on_small_n() {
    let test = FermatTest;
    let values = [0u32, 1]; // убери 2 из списка

    for &v in &values {
        let n = BigUint::from_u32(v).unwrap();
        assert!(!test.is_probably_prime(&n, 0.99), "Fermat incorrectly passed n = {}", v);
    }
}

#[test]
fn test_fermat_on_large_primes_and_composites() {
    let test = FermatTest;

    let prime = BigUint::parse_bytes(b"32416190071", 10).unwrap(); // простое
    let composite = BigUint::parse_bytes(b"32416190071", 10).unwrap() * 3u32;

    assert!(test.is_probably_prime(&prime, 0.99), "Fermat failed on large prime");
    assert!(!test.is_probably_prime(&composite, 0.99), "Fermat failed on large composite");
}

use quickcheck::quickcheck;
use num_bigint::RandBigInt;
use rand::thread_rng;

quickcheck! {
    fn prop_fermat_detects_small_composites(n: u8) -> bool {
        if n < 4 || n % 2 == 1 { return true; } // исключаем слишком малые и нечётные
        let test = FermatTest;
        let n = BigUint::from(n);
        !test.is_probably_prime(&n, 0.99)
    }
}
