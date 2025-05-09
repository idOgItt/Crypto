use crate::primality::{PrimalityTest, fermat::FermatTest, solovay_strassen::SolovayStrassenTest, miller_rabin::MillerRabinTest};
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_traits::One;
use rand::thread_rng;
use crate::number_theory::{extended_gcd, gcd};

/// Выбор теста простоты
pub enum PrimalityType {
    Fermat,
    SolovayStrassen,
    MillerRabin,
}

/// Структура открытого и закрытого ключа RSA
pub struct RsaKeyPair {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    #[doc(hidden)]
    pub(crate) p: BigUint,
    #[doc(hidden)]
    pub(crate) q: BigUint,
}

impl RsaKeyPair {
    #[doc(hidden)]
    pub fn get_p(&self) -> &BigUint {
        &self.p
    }

    #[doc(hidden)]
    pub fn get_q(&self) -> &BigUint {
        &self.q
    }
}




/// Сервис генерации ключей RSA
pub struct RsaKeyGenerator {
    test_type: PrimalityType,
    confidence: f64,
    bit_length: usize,
}

impl RsaKeyGenerator {
    /// Создание нового генератора
    pub fn new(test_type: PrimalityType, confidence: f64, bit_length: usize) -> Self {
        Self { test_type, confidence, bit_length }
    }

    /// Генерация пары ключей RSA, с защитой от атак Ферма и Винера
    pub fn generate_keypair(&self) -> RsaKeyPair {
        let test = self.get_test();
        let one = BigUint::one();
        let e = BigUint::from(65537u32);
        let half_bits = self.bit_length / 2;
        let min_diff = BigUint::one() << (self.bit_length / 4);

        let mut rng = thread_rng();

        loop {
            let p = loop {
                let mut candidate = rng.gen_biguint(half_bits as u64);
                candidate.set_bit((half_bits - 1) as u64, true);
                if test.is_probably_prime(&candidate, self.confidence) {
                    break candidate;
                }
            };

            let q = loop {
                let mut candidate = rng.gen_biguint(half_bits as u64);
                candidate.set_bit((half_bits - 1) as u64, true);
                if candidate != p
                    && test.is_probably_prime(&candidate, self.confidence)
                    && (&p > &candidate && &p - &candidate > min_diff
                    || &candidate > &p && &candidate - &p > min_diff)
                {
                    break candidate;
                }
            };

            let n = &p * &q;
            if n.bits() < self.bit_length as u64 {
                continue; // пробуем заново
            }

            let phi = (&p - &one) * (&q - &one);
            if gcd(&e, &phi) != one {
                continue;
            }

            let (_, d, _) = extended_gcd(&e.to_bigint().unwrap(), &phi.to_bigint().unwrap());
            let d = ((d % &phi.to_bigint().unwrap()) + &phi.to_bigint().unwrap()) % &phi.to_bigint().unwrap();
            let d = d.to_biguint().unwrap();

            if d.bits() < (self.bit_length / 4) as u64 {
                continue;
            }

            return RsaKeyPair { n, e, d, p, q };
        }
    }


    /// Получение экземпляра теста простоты по выбору пользователя
    fn get_test(&self) -> Box<dyn PrimalityTest> {
        match self.test_type {
            PrimalityType::Fermat => Box::new(FermatTest),
            PrimalityType::SolovayStrassen => Box::new(SolovayStrassenTest),
            PrimalityType::MillerRabin => Box::new(MillerRabinTest),
        }
    }
}
