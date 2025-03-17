use crate::crypto::des_adapter::DesAdapter;
use crate::crypto::feistel_network::FeistelNetwork;
use crate::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds};
use crate::crypto::des::DES;

pub struct DEAL {
    feistel_network: FeistelNetwork,
    key: Vec<u8>,
    round_key: Vec<Vec<u8>>,
    des_adapter: DesAdapter,
}

impl DEAL {
    pub fn new(des: DES) -> Self {
        todo!()
    }
    
    pub fn encrypt(&self, block: &[u8], key: &[u8]) -> Vec<u8> {
        todo!()
    }
    
    pub fn decrypt(&self, block: &[u8], key: &[u8]) -> Vec<u8> {
        todo!()
    }
}