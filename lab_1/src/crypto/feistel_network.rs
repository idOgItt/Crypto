use crate::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::key_expansion::KeyExpansion;

pub struct FeistelNetwork {
    num_round : usize,
    key_expansion: Box<dyn KeyExpansion>,
    transformation: Box<dyn EncryptionTransformation>,
}

impl FeistelNetwork {
    pub fn new(num_round: usize, key_expansion: Box<dyn KeyExpansion>) -> Self { panic!("Implement self") }

    pub fn encrypt(&self, block: &[u8], key: &[u8]) -> Vec<u8> { panic!("Implement encrypt") }

    pub fn decrypt(&self, block: &[u8], key: &[u8]) -> Vec<u8> { panic!("Implement decrypt") }
}