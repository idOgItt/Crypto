// src/rijndael/cipher.rs

use crate::gf::arithmetic::Poly;
use crate::rijndael::key_schedule::expand_key;
use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm,
    SymmetricCipher,
    SymmetricCipherWithRounds,
};

/// Encrypts a single 16-byte block with your round keys and GF(2⁸) poly
pub fn aes_encrypt_block(
    block: &[u8;16],
    round_keys: &[Vec<u8>],
    poly: &Poly,
) -> [u8;16] {
    // … ваша SubBytes/ShiftRows/MixColumns/AddRoundKey …
    todo!()
}

/// Decrypts a single 16-byte block
pub fn aes_decrypt_block(
    block: &[u8;16],
    round_keys: &[Vec<u8>],
    poly: &Poly,
) -> [u8;16] {
    // … InvSubBytes/InvShiftRows/InvMixColumns/AddRoundKey …
    todo!()
}

/// Ваш блочный шифр Rijndael (AES) с настраиваемым размером блока
pub struct Rijndael {
    poly:       Poly,
    round_keys: Vec<Vec<u8>>,
    block_size: usize,
}

impl Rijndael {
    /// Создаёт новый Rijndael с данным полиномом и размером блока (в байтах: 16, 24 или 32)
    pub fn new(poly: Poly, block_size: usize) -> Self {
        Self {
            poly,
            round_keys: Vec::new(),
            block_size,
        }
    }
}

impl CipherAlgorithm for Rijndael {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.chunks(self.block_size)
            .flat_map(|chunk| {
                // Подготавливаем ровно block_size байт
                let mut buf = vec![0u8; self.block_size];
                buf[..chunk.len()].copy_from_slice(chunk);
                // Для AES блок всегда 16 байт
                let mut block16 = [0u8;16];
                block16.copy_from_slice(&buf[0..16]);
                aes_encrypt_block(&block16, &self.round_keys, &self.poly)
                    .iter()
                    .copied()
                    .take(chunk.len())
                    .collect::<Vec<u8>>()
            })
            .collect()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.chunks(self.block_size)
            .flat_map(|chunk| {
                let mut buf = vec![0u8; self.block_size];
                buf[..chunk.len()].copy_from_slice(chunk);
                let mut block16 = [0u8;16];
                block16.copy_from_slice(&buf[0..16]);
                aes_decrypt_block(&block16, &self.round_keys, &self.poly)
                    .iter()
                    .copied()
                    .take(chunk.len())
                    .collect::<Vec<u8>>()
            })
            .collect()
    }
}

impl SymmetricCipher for Rijndael {
    fn set_key(&mut self, key: &[u8]) -> Result<(), &'static str> {
        self.round_keys = expand_key(key, &self.poly);
        Ok(())
    }
}

impl SymmetricCipherWithRounds for Rijndael {
    fn set_key_with_rounds(&mut self, key: &[u8]) {
        self.round_keys = expand_key(key, &self.poly);
    }

    fn encrypt_block(&self, block: &[u8], _round_key: &[u8]) -> Vec<u8> {
        let mut b = [0u8; 16];
        b.copy_from_slice(&block[0..16]);
        aes_encrypt_block(&b, &self.round_keys, &self.poly).to_vec()
    }

    fn decrypt_block(&self, block: &[u8], _round_key: &[u8]) -> Vec<u8> {
        let mut b = [0u8; 16];
        b.copy_from_slice(&block[0..16]);
        aes_decrypt_block(&b, &self.round_keys, &self.poly).to_vec()
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        Some(self.round_keys.iter().flatten().copied().collect())
    }
}
