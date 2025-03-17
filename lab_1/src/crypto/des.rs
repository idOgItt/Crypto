use crate::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds};
use crate::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::feistel_network::FeistelNetwork;
use crate::crypto::key_expansion::KeyExpansion;

pub struct DES {
    feistel_network : FeistelNetwork,
    key_expansion : Box<dyn KeyExpansion>,
    transformation: Box<dyn EncryptionTransformation>,
    round_key : Vec<Vec<u8>>,
    key : Vec<u8>,
}

impl DES {
    pub fn new(key_expansion: Box<dyn KeyExpansion>, transformation: Box<dyn EncryptionTransformation>) -> Self {
    panic!("Implement self");}

    pub fn encrypt(&self, block: &[u8]) -> Vec<u8> { panic!("Implement encrypt") }

    pub fn decrypt(&self, block: &[u8]) -> Vec<u8> { panic!("Implement decrypt") }
}

impl CipherAlgorithm for DES {
    fn encrypt(&self, block: &[u8]) -> Vec<u8> {panic!("Implement encrypt") }
    fn decrypt(&self, block: &[u8]) -> Vec<u8> {panic!("Implement decrypt") }
}

impl SymmetricCipher for DES {
    fn set_key(&mut self, key: &[u8]) {
        todo!()
    }
}

impl SymmetricCipherWithRounds for DES {
    fn set_key_with_rounds(&mut self, key: &[u8]) {
        todo!()
    }

    fn encrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8> {
        todo!()
    }

    fn decrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8> {
        todo!()
    }
}