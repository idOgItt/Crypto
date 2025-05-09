// Только если вам нужен совместимый KeyExpansion
use crate::crypto::key_expansion::KeyExpansion;
use crate::gf::arithmetic::Poly;

/// Генерация всех раундовых ключей
pub fn expand_key(key: &[u8], poly: &Poly) -> Vec<Vec<u8>> {
    todo!("Key schedule AES с использованием sbox и poly")
}
/// Обёртка-генератор ключей для AES, реализующая trait из symmetric_cipher
pub struct AesKeyExpansion {
    poly: Poly,
}

impl AesKeyExpansion {
    pub fn new(poly: Poly) -> Self {
        Self { poly }
    }
}

impl KeyExpansion for AesKeyExpansion {
    fn generate_round_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        // делегируем на свободную функцию
        expand_key(key, &self.poly)
    }
}
