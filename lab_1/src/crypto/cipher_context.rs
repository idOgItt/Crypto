use crate::crypto::cipher_traits::SymmetricCipherWithRounds;
use crate::crypto::cipher_types::{CipherInput, CipherMode, CipherOutput, PaddingMode};

pub struct CipherContext {
    algorithm : Box<dyn SymmetricCipherWithRounds + Sync + Send>,
    mode : CipherMode,
    padding : PaddingMode,
    iv: Option<Vec<u8>>,
    additional_params: Vec<u8>,
}

impl CipherContext {
    pub fn new(
        algorithm: Box<dyn SymmetricCipherWithRounds + Send + Sync>,
        mode: CipherMode,
        padding: PaddingMode,
        iv: Option<Vec<u8>>,
        additional_params: Vec<u8>,
    ) -> Self {panic!("Implement Self")}

    pub fn set_key(&mut self, key: &[u8]) {panic!("Implement set_key")}

    pub async fn encrypt(&self, input: CipherInput, output: CipherOutput) -> std::io::Result<()>{panic!("Implement encrypt")}

    pub async fn decrypt(&self, input: CipherInput, output: CipherOutput) -> std::io::Result<()>{panic!("Implement decrypt")}
}