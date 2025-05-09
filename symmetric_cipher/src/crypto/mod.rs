pub mod cipher_context;
pub mod feistel_network;
pub mod des;
pub mod deal;
pub mod key_expansion;
pub mod encryption_transformation;
pub mod cipher_traits;
pub mod utils;
pub mod cipher_types;
mod des_adapter;
mod cipher_io;
pub mod des_tables;
pub mod des_transformation;
pub mod des_key_expansion;
pub mod deal_key_expansion;

use std::sync::Arc;
use crate::crypto::key_expansion::KeyExpansion;
use crate::crypto::encryption_transformation::EncryptionTransformation;

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
