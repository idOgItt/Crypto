use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds,
};
use crate::crypto::key_schedule::expand_key;
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

    /// Encrypt one 128-bit block via 16‐round Feistel.
    fn feistel_encrypt_block(&self, block: &[u8]) -> Vec<u8> {
        assert_eq!(block.len(), 16, "Block must be 16 bytes (128 bits)");

        let mut left = block[0..8].to_vec();
        let mut right = block[8..16].to_vec();

        for &sk in &self.round_keys {
            let r_u64 = u64::from_be_bytes(right.clone().try_into().unwrap());
            let f_out = round_function(r_u64, sk);

            let f_bytes = f_out.to_be_bytes();

            let new_right: Vec<u8> = left.iter()
                .zip(f_bytes.iter())
                .map(|(a, b)| a ^ b)
                .collect();

            left = right;
            right = new_right;
        }

        [right, left].concat()
    }

    /// Decrypt one 128-bit block via 16‐round Feistel.
    fn feistel_decrypt_block(&self, block: &[u8]) -> Vec<u8> {
        assert_eq!(block.len(), 16, "Block must be 16 bytes (128 bits)");

        let mut right = block[0..8].to_vec();
        let mut left = block[8..16].to_vec();

        for &sk in self.round_keys.iter().rev() {
            let l_u64 = u64::from_be_bytes(left.clone().try_into().unwrap());
            let f_out = round_function(l_u64, sk);

            let f_bytes = f_out.to_be_bytes();

            let new_left: Vec<u8> = right.iter()
                .zip(f_bytes.iter())
                .map(|(a, b)| a ^ b)
                .collect();

            right = left;
            left = new_left;
        }

        [left, right].concat()
    }
}

impl CipherAlgorithm for Loki97Cipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len() % 16, 0, "Data length must be multiple of 16");
        data.chunks_exact(16)
            .flat_map(|chunk| {
                self.feistel_encrypt_block(chunk)
            })
            .collect()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len() % 16, 0, "Data length must be multiple of 16");
        data.chunks_exact(16)
            .flat_map(|chunk| {
                self.feistel_decrypt_block(chunk)
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
        16
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
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
        tmp.feistel_encrypt_block(block)
    }

    fn decrypt_block(&self, block: &[u8], raw_round_keys: &[u8]) -> Vec<u8> {
        let mut tmp = self.clone();
        tmp.set_key_with_rounds(raw_round_keys);
        tmp.feistel_decrypt_block(block)
    }
}