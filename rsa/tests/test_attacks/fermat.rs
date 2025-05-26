use rsa::attacks::fermat::{FermatAttack, FermatAttackResult};
use num_bigint::{BigUint, ToBigInt, ToBigUint};
use rsa::number_theory::extended_gcd;

#[test]
fn test_fermat_attack_success() {
    let p = 10007u32.to_biguint().unwrap();
    let q = 10009u32.to_biguint().unwrap();
    let n = &p * &q;
    let phi_n = (&p - 1u32) * (&q - 1u32);
    let e = 65537u32.to_biguint().unwrap();

    let (_, mut d, _) = extended_gcd(&e.to_bigint().unwrap(), &phi_n.to_bigint().unwrap());
    let phi_bigint = phi_n.to_bigint().unwrap();
    d = ((d % &phi_bigint) + &phi_bigint) % &phi_bigint;
    let d = d.to_biguint().unwrap();

    let result = FermatAttack::attack(&n, &e).expect("Атака не удалась");

    assert_eq!(result.d, d);
    assert_eq!(result.phi_n, phi_n);
    assert!(result.p == p || result.p == q);
    assert!(result.q == p || result.q == q);
}

#[test]
fn test_fermat_attack_failure() {
    let p = 10007u32.to_biguint().unwrap();
    let q = 30011u32.to_biguint().unwrap(); // далеко от p
    let n = &p * &q;
    let e = 65537u32.to_biguint().unwrap();

    let result = FermatAttack::attack(&n, &e);
    assert!(result.is_none(), "Атака не должна была сработать");
}

#[test]
fn test_fermat_attack_on_small_n() {
    let n = 15u32.to_biguint().unwrap(); // 3 * 5
    let e = 3u32.to_biguint().unwrap();

    let result = FermatAttack::attack(&n, &e);
    assert!(result.is_none(), "Атака не должна работать на таких маленьких значениях");
}

#[test]
fn test_fermat_attack_on_equal_primes() {
    let p = 10007u32.to_biguint().unwrap();
    let n = &p * &p; // p = q
    let phi_n = (&p - 1u32) * (&p - 1u32);
    let e = 17u32.to_biguint().unwrap();
    let (_, mut d, _) = extended_gcd(&e.to_bigint().unwrap(), &phi_n.to_bigint().unwrap());
    let phi_bigint = phi_n.to_bigint().unwrap();
    d = ((d % &phi_bigint) + &phi_bigint) % &phi_bigint;
    let d = d.to_biguint().unwrap();
    let result = FermatAttack::attack(&n, &e).expect("Ожидался успех атаки");

    assert_eq!(result.d, d);
    assert_eq!(result.phi_n, phi_n);
    assert_eq!(result.p, p);
    assert_eq!(result.q, p);
}

#[test]
fn test_fermat_attack_on_close_primes() {
    let p = 65537u32.to_biguint().unwrap();
    let q = (&p + 2u32).to_biguint().unwrap(); // очень близко
    let n = &p * &q;
    let phi_n = (&p - 1u32) * (&q - 1u32);
    let e = 17u32.to_biguint().unwrap();
    let (_, mut d, _) = extended_gcd(&e.to_bigint().unwrap(), &phi_n.to_bigint().unwrap());
    let phi_bigint = phi_n.to_bigint().unwrap();
    d = ((d % &phi_bigint) + &phi_bigint) % &phi_bigint;
    let d = d.to_biguint().unwrap();
    let result = FermatAttack::attack(&n, &e).expect("Атака не удалась");

    assert_eq!(result.d, d);
    assert_eq!(result.phi_n, phi_n);
    assert!(result.p == p || result.p == q);
    assert!(result.q == p || result.q == q);
}
