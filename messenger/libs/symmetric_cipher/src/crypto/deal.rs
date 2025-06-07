use crate::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds};
pub use crate::crypto::deal_key_expansion::DealKeyExpansion;
use crate::crypto::des::DES;
use crate::crypto::des_adapter::DesAdapter;
use crate::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::feistel_network::FeistelNetwork;
use crate::crypto::key_expansion::KeyExpansion;
use std::sync::Arc;

pub struct DEAL {
    feistel_network: FeistelNetwork,
    key: Vec<u8>,
    round_key: Vec<Vec<u8>>,
    key_expansion: DealKeyExpansion,
}

impl DEAL {
    pub fn new(des: DES) -> Self {
        let key_expansion_struct = DealKeyExpansion;
        let key_exp_arc: Arc<dyn KeyExpansion + Send + Sync> =
            Arc::new(key_expansion_struct.clone());

        let des_adapter_arc: Arc<dyn EncryptionTransformation + Send + Sync> =
            Arc::new(DesAdapter::new());

        let feistel_network = FeistelNetwork::new(32, key_exp_arc.clone(), des_adapter_arc.clone());

        DEAL {
            feistel_network,
            key: Vec::new(),
            round_key: Vec::new(),
            key_expansion: key_expansion_struct,
        }
    }

    pub fn encrypt(&self, block: &[u8], key: &[u8]) -> Vec<u8> {
        let round_keys = self.key_expansion.generate_round_keys(key);
        self.feistel_network
            .encrypt_with_round_keys(block, &round_keys)
    }

    pub fn decrypt(&self, block: &[u8], key: &[u8]) -> Vec<u8> {
        let round_keys = self.key_expansion.generate_round_keys(key);
        self.feistel_network
            .decrypt_with_round_keys(block, &round_keys)
    }
}

impl CipherAlgorithm for DEAL {
    fn encrypt(&self, block: &[u8]) -> Vec<u8> {
        self.feistel_network
            .encrypt_with_round_keys(block, &self.round_key)
    }

    fn decrypt(&self, block: &[u8]) -> Vec<u8> {
        self.feistel_network
            .decrypt_with_round_keys(block, &self.round_key)
    }
}

impl SymmetricCipher for DEAL {
    fn set_key(&mut self, key: &[u8]) -> Result<(), &'static str> {
        if key.len() != 24 {
            return Err("DEAL key must be 24 bytes (192 bits)");
        }
        self.key = key.to_vec();
        self.round_key = self.key_expansion.generate_round_keys(key);
        Ok(())
    }
}

impl SymmetricCipherWithRounds for DEAL {
    fn set_key_with_rounds(&mut self, key: &[u8]) {
        self.set_key(key).unwrap();
    }

    fn encrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8> {
        self.feistel_network
            .encrypt_with_round_keys(data, &self.round_key)
    }

    fn decrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8> {
        self.feistel_network
            .decrypt_with_round_keys(data, &self.round_key)
    }

    fn block_size(&self) -> usize {
        8
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        None
    }
}
