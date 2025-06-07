use crate::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::key_expansion::KeyExpansion;
use std::sync::Arc;

pub struct FeistelNetwork {
    num_round: usize,
    key_expansion: Arc<dyn KeyExpansion + Send + Sync>,
    transformation: Arc<dyn EncryptionTransformation + Send + Sync>,
}

impl FeistelNetwork {
    pub fn new(
        num_round: usize,
        key_expansion: Arc<dyn KeyExpansion + Send + Sync>,
        transformation: Arc<dyn EncryptionTransformation + Send + Sync>,
    ) -> Self {
        Self {
            num_round,
            key_expansion,
            transformation,
        }
    }

    pub fn encrypt_with_round_keys(&self, block: &[u8], round_keys: &[Vec<u8>]) -> Vec<u8> {
        assert_eq!(block.len() % 2, 0, "Block size must be even");

        let (left, right) = block.split_at(block.len() / 2);

        let mut left = left.to_vec();
        let mut right = right.to_vec();

        for index in 0..self.num_round {
            let feistel_out = self.transformation.transform(&right, &round_keys[index]);
            let new_right = left
                .iter()
                .zip(feistel_out.iter())
                .map(|(a, b)| a ^ b)
                .collect();
            left = right;
            right = new_right;
        }
        [left, right].concat()
    }

    pub fn decrypt_with_round_keys(&self, block: &[u8], round_keys: &[Vec<u8>]) -> Vec<u8> {
        assert_eq!(block.len() % 2, 0, "Block size must be even");

        let (left, right) = block.split_at(block.len() / 2);

        let mut left = left.to_vec();
        let mut right = right.to_vec();

        for index in (0..self.num_round).rev() {
            let feistel_out = self.transformation.transform(&left, &round_keys[index]);
            let new_left = right
                .iter()
                .zip(feistel_out.iter())
                .map(|(a, b)| a ^ b)
                .collect();
            right = left;
            left = new_left;
        }

        [left, right].concat()
    }
}
