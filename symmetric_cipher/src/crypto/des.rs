use crate::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds};
use crate::crypto::des_tables::{FP, IP};
use crate::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::feistel_network::FeistelNetwork;
use crate::crypto::key_expansion::KeyExpansion;
use crate::crypto::utils::shift_bits_little_endian;
use std::sync::Arc;

pub struct DES {
    feistel_network: FeistelNetwork,
    key_expansion: Arc<dyn KeyExpansion + Send + Sync>,
    transformation: Arc<dyn EncryptionTransformation + Send + Sync>,
    round_key: Vec<Vec<u8>>,
    key: Vec<u8>,
}

impl DES {
    pub fn new(
        key_expansion: Arc<dyn KeyExpansion + Send + Sync>,
        transformation: Arc<dyn EncryptionTransformation + Send + Sync>,
    ) -> Self {
        let feistel_network =
            FeistelNetwork::new(16, key_expansion.clone(), transformation.clone());

        DES {
            feistel_network,
            key_expansion,
            transformation,
            round_key: Vec::new(),
            key: Vec::new(),
        }
    }

    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        let permuted = shift_bits_little_endian(block, &IP, true, 1);
        let result = self.feistel_network.encrypt_with_round_keys(&permuted, &self.round_key);
        shift_bits_little_endian(&result, &FP, true, 1)
    }

    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        let permuted = shift_bits_little_endian(block, &IP, true, 1);
        let result = self.feistel_network.decrypt_with_round_keys(&permuted, &self.round_key);
        shift_bits_little_endian(&result, &FP, true, 1)
    }
}

impl CipherAlgorithm for DES {
    fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        DES::encrypt(self, block)
    }
    fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        DES::decrypt(self, block)
    }
}

impl SymmetricCipher for DES {
    fn set_key(&mut self, key: &[u8]) -> Result<(), &'static str> {
        if key.len() != 8 {
            return Err("DES key must be 8 bytes");
        }
        self.key = key.to_vec();
        self.round_key = self.key_expansion.generate_round_keys(key);
        Ok(())
    }
}

impl SymmetricCipherWithRounds for DES {
    fn set_key_with_rounds(&mut self, key: &[u8]) {
        assert_eq!(key.len(), 8, "DES key must be 8 bytes");
        self.key = key.to_vec();
        self.round_key = self.key_expansion.generate_round_keys(key);
    }

    fn encrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }

    fn decrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8> {
        self.decrypt(data)
    }

    fn block_size(&self) -> usize {
        8
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        None
    }
}
