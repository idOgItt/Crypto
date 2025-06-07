pub trait EncryptionTransformation {
    fn transform(&self, input_block: &[u8], round_key: &[u8]) -> Vec<u8>;
}
