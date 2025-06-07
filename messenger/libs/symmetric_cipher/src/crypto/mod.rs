pub mod cipher_context;
mod cipher_io;
pub mod cipher_traits;
pub mod cipher_types;
pub mod deal;
pub mod deal_key_expansion;
pub mod des;
mod des_adapter;
pub mod des_key_expansion;
pub mod des_tables;
pub mod des_transformation;
pub mod encryption_transformation;
pub mod feistel_network;
pub mod key_expansion;
pub mod utils;

use crate::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::key_expansion::KeyExpansion;
use std::sync::Arc;

impl KeyExpansion for Arc<dyn KeyExpansion> {
    fn generate_round_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        (**self).generate_round_keys(key)
    }
}

impl EncryptionTransformation for Arc<dyn EncryptionTransformation> {
    fn transform(&self, input_block: &[u8], round_key: &[u8]) -> Vec<u8> {
        (**self).transform(input_block, round_key)
    }
}
