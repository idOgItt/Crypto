use symmetric_cipher::crypto::feistel_network::FeistelNetwork;
use symmetric_cipher::crypto::key_expansion::KeyExpansion;
use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    struct MockKeyExpansion;
    impl KeyExpansion for MockKeyExpansion {
        fn generate_round_keys(&self, _key: &[u8]) -> Vec<Vec<u8>> {
            vec![vec![0x0F; 4]; 3]
        }
    }

    struct MockTransformation;
    impl EncryptionTransformation for MockTransformation {
        fn transform(&self, block: &[u8], round_key: &[u8]) -> Vec<u8> {
            block.iter()
                .zip(round_key.iter().cycle())
                .map(|(b, k)| b ^ k)
                .collect()
        }
    }

    #[test]
    fn test_feistel_encrypt_decrypt_roundtrip() {
        let network = FeistelNetwork::new(
            3,
            Arc::new(MockKeyExpansion) as Arc<dyn KeyExpansion + Send + Sync>,
            Arc::new(MockTransformation) as Arc<dyn EncryptionTransformation + Send + Sync>,
        );

        let key = b"dummykey";
        let block = b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0";

        let key_expansion = MockKeyExpansion;
        let round_keys = key_expansion.generate_round_keys(key);

        let encrypted = network.encrypt_with_round_keys(block, &round_keys);
        let decrypted = network.decrypt_with_round_keys(&encrypted, &round_keys);

        assert_eq!(decrypted, block);
    }

    #[test]
    fn test_feistel_block_size_even() {
        let network = FeistelNetwork::new(
            3,
            Arc::new(MockKeyExpansion) as Arc<dyn KeyExpansion + Send + Sync>,
            Arc::new(MockTransformation) as Arc<dyn EncryptionTransformation + Send + Sync>,
        );

        let key = b"dummykey";
        let block = b"\x00\x11\x22\x33\x44\x55\x66\x77";

        let key_expansion = MockKeyExpansion;
        let round_keys = key_expansion.generate_round_keys(key);

        let encrypted = network.encrypt_with_round_keys(block, &round_keys);
        assert_eq!(encrypted.len(), block.len());

        let decrypted = network.decrypt_with_round_keys(&encrypted, &round_keys);
        assert_eq!(decrypted, block);
    }
}
