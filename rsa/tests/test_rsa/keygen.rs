use rsa::rsa::keygen::{RsaKeyGenerator, PrimalityType};
use rsa::primality::{PrimalityTest, MillerRabinTest};
use num_bigint::{BigUint, ToBigUint};
use num_traits::{FromPrimitive};
use quickcheck::quickcheck;
use rand::Rng;

#[test]
fn test_key_generation_basic() {
    let generator = RsaKeyGenerator::new(PrimalityType::MillerRabin, 0.99, 64);
    let keypair = generator.generate_keypair();

    assert!(keypair.e.bits() > 1);
    assert!(keypair.d.bits() > 1);
    assert!(keypair.n.bits() >= 64);
}

#[test]
fn test_key_generation_encrypt_decrypt_cycle() {
    let generator = RsaKeyGenerator::new(PrimalityType::MillerRabin, 0.99, 64);
    let keypair = generator.generate_keypair();

    let m = BigUint::from_u32(42).unwrap();
    let c = m.modpow(&keypair.e, &keypair.n);
    let m_recovered = c.modpow(&keypair.d, &keypair.n);

    assert_eq!(m, m_recovered);
}

#[test]
fn test_key_generation_modinv_check() {
    let generator = RsaKeyGenerator::new(PrimalityType::MillerRabin, 0.99, 64);
    let keypair = generator.generate_keypair();

    let phi_n = (keypair.get_p() - 1u32) * (keypair.get_q() - 1u32);
    let ed_mod_phi = (&keypair.e * &keypair.d) % &phi_n;

    assert_eq!(ed_mod_phi, BigUint::from_u32(1).unwrap());
}

#[test]
fn test_key_generation_prime_checks() {
    let generator = RsaKeyGenerator::new(PrimalityType::MillerRabin, 0.99, 64);
    let keypair = generator.generate_keypair();
    let primality = MillerRabinTest;

    assert!(keypair.get_p() != keypair.get_q(), "p и q не должны совпадать");
    assert!(primality.is_probably_prime(keypair.get_p(), 0.99));
    assert!(primality.is_probably_prime(keypair.get_q(), 0.99));
}

#[test]
fn test_key_bit_lengths() {
    let generator = RsaKeyGenerator::new(PrimalityType::Fermat, 0.99, 128);
    let keypair = generator.generate_keypair();

    assert!(keypair.n.bits() >= 128);
    assert!(keypair.e.bits() > 1);
    assert!(keypair.d.bits() > 1);
}

quickcheck! {
    fn prop_keygen_encrypt_decrypt_cycle(val: u8) -> bool {
        let generator = RsaKeyGenerator::new(PrimalityType::MillerRabin, 0.99, 64);
        let keypair = generator.generate_keypair();

        let m = BigUint::from(val);
        if m >= keypair.n {
            return true;
        }

        let c = m.modpow(&keypair.e, &keypair.n);
        let m_recovered = c.modpow(&keypair.d, &keypair.n);
        m == m_recovered
    }
}
