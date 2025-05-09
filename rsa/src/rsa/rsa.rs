use crate::rsa::keygen::{RsaKeyGenerator, RsaKeyPair, PrimalityType};
use num_bigint::{BigUint};
use num_traits::ToPrimitive;
use crate::number_theory::mod_pow;

/// Основной RSA-сервис: обёртка для шифрования и дешифрования
pub struct RsaService {
    keypair: RsaKeyPair,
}

impl RsaService {
    /// Создание RSA-сервиса с параметрами генерации ключей
    pub fn new(test_type: PrimalityType, confidence: f64, bit_length: usize) -> Self {
        let generator = RsaKeyGenerator::new(test_type, confidence, bit_length);
        let keypair = generator.generate_keypair();
        Self { keypair }
    }

    /// Шифрование: c = m^e mod n
    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        if m >= &self.keypair.n {
            panic!("message too large");
        }
        m.modpow(&self.keypair.e, &self.keypair.n)
    }


    /// Дешифрование: m = c^d mod n
    pub fn decrypt(&self, ciphertext: &BigUint) -> BigUint {
        mod_pow(ciphertext, &self.keypair.d, &self.keypair.n)
    }

    /// Доступ к открытому ключу (n, e)
    pub fn public_key(&self) -> (BigUint, BigUint) {
        (self.keypair.n.clone(), self.keypair.e.clone())
    }

    /// Доступ к закрытому ключу (n, d)
    pub fn private_key(&self) -> (BigUint, BigUint) {
        (self.keypair.n.clone(), self.keypair.d.clone())
    }
}
