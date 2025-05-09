pub trait CipherAlgorithm {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub trait SymmetricCipher: CipherAlgorithm {
    fn set_key(&mut self, _: &[u8]) -> Result<(), &'static str>;
}

pub trait SymmetricCipherWithRounds: SymmetricCipher {
    fn set_key_with_rounds(&mut self, key: &[u8]);
    fn encrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8>;
    fn decrypt_block(&self, data: &[u8], round_key: &[u8]) -> Vec<u8>;
    fn block_size(&self) -> usize;
    fn export_round_keys(&self) -> Option<Vec<u8>>;
}
