use rsa::attacks::wiener::{WienerAttack, WienerAttackResult};
use rsa::number_theory::extended_gcd;
use rsa::primality::{MillerRabinTest, PrimalityTest};

use num_bigint::{BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_traits::{FromPrimitive, One, Zero};
use quickcheck::quickcheck;
use rand::thread_rng;

fn gen_prime(bits: u64) -> BigUint {
    let mut rng = thread_rng();
    let test = MillerRabinTest;
    loop {
        let candidate = rng.gen_biguint(bits);
        if test.is_probably_prime(&candidate, 0.99) {
            return candidate;
        }
    }
}

quickcheck! {
    fn prop_wiener_attack_detects_small_d(bits: u64) -> bool {
        if bits < 8 || bits > 20 { return true; }
        let p = gen_prime(bits);
        let mut q;
        loop {
            q = gen_prime(bits);
            if q != p { break; }
        }

        let n = &p * &q;
        let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

        let d = BigUint::from(3u8);
        let phi_bigint = phi_n.to_bigint().unwrap();
        let (_, mut e_big, _) = extended_gcd(&d.to_bigint().unwrap(), &phi_bigint);
        e_big = ((e_big % &phi_bigint) + &phi_bigint) % &phi_bigint;
        let e = e_big.to_biguint().unwrap();

        let result = WienerAttack::attack(&n, &e);
        match result {
            Some(r) => r.d == d,
            None => false,
        }
    }
}

#[test]
fn test_wiener_attack_e_zero() {
    let n = BigUint::from_u64(90581).unwrap();
    let e = BigUint::zero();

    let result = WienerAttack::attack(&n, &e);
    assert!(result.is_none(), "Атака не должна работать при e = 0");
}

#[test]
fn test_wiener_attack_invalid_n() {
    let e = BigUint::from_u64(3).unwrap();
    for n in [0u64, 1u64] {
        let n = BigUint::from_u64(n).unwrap();
        let result = WienerAttack::attack(&n, &e);
        assert!(result.is_none(), "Атака не должна работать при n = {}", n);
    }
}

#[test]
fn test_wiener_attack_e_ge_n() {
    let n = BigUint::from_u64(65537).unwrap();
    let e = BigUint::from_u64(70000).unwrap();
    let result = WienerAttack::attack(&n, &e);
    assert!(result.is_none(), "Атака не должна работать при e >= n");
}

#[test]
fn test_wiener_attack_too_small_n() {
    let n = BigUint::from_u64(35).unwrap();
    let e = BigUint::from_u64(3).unwrap();
    let result = WienerAttack::attack(&n, &e);
    assert!(
        result.is_none(),
        "Атака не должна сработать для слишком малого n"
    );
}

#[test]
fn test_wiener_attack_end_to_end() {
    let p = BigUint::from(277u32);
    let q = BigUint::from(331u32);
    let n = &p * &q;
    let phi_n = (&p - 1u32) * (&q - 1u32);

    let d = BigUint::from(17u32);
    let phi_bigint = phi_n.to_bigint().unwrap();
    let (_, mut e_big, _) = extended_gcd(&d.to_bigint().unwrap(), &phi_bigint);
    e_big = ((e_big % &phi_bigint) + &phi_bigint) % &phi_bigint;
    let e = e_big.to_biguint().unwrap();

    let m = BigUint::from(42u32);
    let c = m.modpow(&e, &n);

    let result = WienerAttack::attack(&n, &e).expect("Wiener attack failed");
    assert_eq!(result.d, d);

    let m_recovered = c.modpow(&result.d, &n);
    assert_eq!(m_recovered, m);
}
