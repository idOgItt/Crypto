use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rsa::rsa::keygen::PrimalityType;
use rsa::rsa::rsa::RsaService;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let service = RsaService::new(PrimalityType::MillerRabin, 0.99, 64);
    let message = BigUint::from(42u32);

    let encrypted = service.encrypt(&message);
    let decrypted = service.decrypt(&encrypted);

    assert_eq!(message, decrypted);
}

#[test]
fn test_encrypt_zero_and_one() {
    let service = RsaService::new(PrimalityType::SolovayStrassen, 0.99, 64);
    let zero = BigUint::zero();
    let one = BigUint::one();

    assert_eq!(service.decrypt(&service.encrypt(&zero)), zero);
    assert_eq!(service.decrypt(&service.encrypt(&one)), one);
}

#[test]
fn test_encrypt_message_too_large() {
    let result = std::panic::catch_unwind(|| {
        let service = RsaService::new(PrimalityType::Fermat, 0.99, 64);
        let (n, _) = service.public_key();
        let m = &n + 1u32;
        service.encrypt(&m);
    });

    assert!(result.is_err(), "encrypt() должен паниковать на слишком большом сообщении");
}

#[test]
fn test_encrypt_decrypt_random_messages() {
    let service = RsaService::new(PrimalityType::MillerRabin, 0.99, 64);
    let (n, _) = service.public_key();
    let mut rng = rand::thread_rng();

    for _ in 0..10 {
        let m = rng.gen_biguint_range(&BigUint::from(2u32), &n);
        let c = service.encrypt(&m);
        let m_recovered = service.decrypt(&c);
        assert_eq!(m, m_recovered);
    }
}

#[test]
fn test_encrypt_decrypt_near_n() {
    let service = RsaService::new(PrimalityType::MillerRabin, 0.99, 64);
    let (n, _) = service.public_key();

    let m = &n - 1u32;
    let c = service.encrypt(&m);
    let m_recovered = service.decrypt(&c);
    assert_eq!(m, m_recovered);
}

use quickcheck::quickcheck;

quickcheck! {
    fn prop_encrypt_decrypt_roundtrip(x: u8) -> bool {
        let service = RsaService::new(PrimalityType::MillerRabin, 0.99, 64);
        let m = BigUint::from(x);
        let (n, _) = service.public_key();

        if m >= n {
            return true; 
        }

        let c = service.encrypt(&m);
        let m_recovered = service.decrypt(&c);
        m == m_recovered
    }
}

#[test]
fn test_encrypt_deterministic() {
    let service = RsaService::new(PrimalityType::MillerRabin, 0.99, 64);
    let m = BigUint::from(123u32);

    let c1 = service.encrypt(&m);
    let c2 = service.encrypt(&m);
    assert_eq!(
        c1, c2,
        "Шифрование RSA должно быть детерминированным без паддинга"
    );
}
