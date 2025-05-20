// src/crypto/loki97.rs

use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds,
};
use crate::crypto::key_schedule::expand_key; // returns Vec<u64> of length 48
use crate::crypto::f_function::round_function;

#[derive(Clone)]
pub struct Loki97Cipher {
    /// Exactly 16 round‐keys (64-bit each) used in the Feistel network
    round_keys: Vec<u64>,
}

impl Loki97Cipher {
    /// Create a new cipher, deriving 48 subkeys but keeping only the first 16.
    pub fn new(master_key: &[u8]) -> Self {
        let all_keys = expand_key(master_key);
        assert!(all_keys.len() >= 16, "Key schedule must produce ≥16 words");
        let rk = all_keys.into_iter().take(16).collect();
        Loki97Cipher { round_keys: rk }
    }

    /// Encrypt one 64-bit block via 16‐round Feistel.
    fn feistel_encrypt_block_u64(&self, block: u64) -> u64 {
        let mut l = (block >> 32) as u32;
        let mut r = block as u32;
        for &sk in &self.round_keys {
            let f_out = round_function(r as u64, sk) as u32;
            let new_l = r;
            let new_r = l ^ f_out;
            l = new_l;
            r = new_r;
        }
        ((r as u64) << 32) | (l as u64)
    }

    /// Decrypt one 64-bit block via 16‐round Feistel.
    fn feistel_decrypt_block_u64(&self, block: u64) -> u64 {
        let mut r = (block >> 32) as u32;
        let mut l = block as u32;
        for &sk in self.round_keys.iter().rev() {
            let f_out = round_function(l as u64, sk) as u32;
            let new_r = l;
            let new_l = r ^ f_out;
            l = new_l;
            r = new_r;
        }
        ((l as u64) << 32) | (r as u64)
    }
}

impl CipherAlgorithm for Loki97Cipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len() % 8, 0, "Data length must be multiple of 8");
        data.chunks_exact(8)
            .flat_map(|chunk| {
                let blk = u64::from_be_bytes(chunk.try_into().unwrap());
                let enc = self.feistel_encrypt_block_u64(blk);
                enc.to_be_bytes()
            })
            .collect()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len() % 8, 0, "Data length must be multiple of 8");
        data.chunks_exact(8)
            .flat_map(|chunk| {
                let blk = u64::from_be_bytes(chunk.try_into().unwrap());
                let dec = self.feistel_decrypt_block_u64(blk);
                dec.to_be_bytes()
            })
            .collect()
    }
}

impl SymmetricCipher for Loki97Cipher {
    fn set_key(&mut self, master_key: &[u8]) -> Result<(), &'static str> {
        if master_key.len() > 32 {
            return Err("Key too long (max 32 bytes)");
        }
        let all_keys = expand_key(master_key);
        assert!(all_keys.len() >= 16);
        self.round_keys = all_keys.into_iter().take(16).collect();
        Ok(())
    }
}

impl SymmetricCipherWithRounds for Loki97Cipher {
    fn block_size(&self) -> usize {
        8
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        // 16 × 8 = 128 bytes
        Some(self
            .round_keys
            .iter()
            .flat_map(|&k| k.to_be_bytes())
            .collect())
    }

    fn set_key_with_rounds(&mut self, raw: &[u8]) {
        assert_eq!(raw.len(), 16 * 8, "Expected 128 bytes of round keys");
        self.round_keys = raw
            .chunks_exact(8)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
            .collect();
    }

    fn encrypt_block(&self, block: &[u8], raw_round_keys: &[u8]) -> Vec<u8> {
        let mut tmp = self.clone();
        tmp.set_key_with_rounds(raw_round_keys);
        let blk = u64::from_be_bytes(block.try_into().unwrap());
        let enc = tmp.feistel_encrypt_block_u64(blk);
        enc.to_be_bytes().to_vec()
    }

    fn decrypt_block(&self, block: &[u8], raw_round_keys: &[u8]) -> Vec<u8> {
        let mut tmp = self.clone();
        tmp.set_key_with_rounds(raw_round_keys);
        let blk = u64::from_be_bytes(block.try_into().unwrap());
        let dec = tmp.feistel_decrypt_block_u64(blk);
        dec.to_be_bytes().to_vec()
    }
}
