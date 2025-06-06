use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::f_function::round_function;
use crate::crypto::loki97::Loki97Cipher;
use crate::symmetric_crypto::key_expansion::KeyExpansion;

pub fn expand_key(master_key: &[u8]) -> Vec<u64> {
    let mut key_material = [0u8; 32];
    key_material[..master_key.len()].copy_from_slice(master_key);

    let mut word_4 = u64::from_be_bytes(key_material[0..8].try_into().unwrap());
    let mut word_3 = u64::from_be_bytes(key_material[8..16].try_into().unwrap());
    let mut word_2 = u64::from_be_bytes(key_material[16..24].try_into().unwrap());
    let mut word_1 = u64::from_be_bytes(key_material[24..32].try_into().unwrap());

    const ROUND_CONSTANT: u64 = 0x9E3779B97F4A7C15;

    let mut round_keys = Vec::with_capacity(48);
    for round_index in 1..=48 {
        let round_input = word_1
            .wrapping_add(word_3)
            .wrapping_add(ROUND_CONSTANT.wrapping_mul(round_index));
        let round_output = round_function(round_input, word_2);

        let updated_word_1 = word_4 ^ round_output;
        let updated_word_2 = word_1;
        let updated_word_3 = word_2;
        let updated_word_4 = word_3;

        word_1 = updated_word_1;
        word_2 = updated_word_2;
        word_3 = updated_word_3;
        word_4 = updated_word_4;

        round_keys.push(word_1);
    }
    round_keys
}

impl KeyExpansion for Loki97Cipher {
    fn generate_round_keys(&self, master_key: &[u8]) -> Vec<Vec<u8>> {
        let round_keys_64 = expand_key(master_key);
        round_keys_64
            .into_iter()
            .map(|key| key.to_be_bytes().to_vec())
            .collect()
    }
}

impl EncryptionTransformation for Loki97Cipher {
    fn transform(&self, plaintext_block: &[u8], round_key: &[u8]) -> Vec<u8> {
        let input_value = u64::from_be_bytes(plaintext_block.try_into().expect("block must be 8 bytes"));
        let round_key_value = u64::from_be_bytes(round_key.try_into().expect("round_key must be 8 bytes"));
        let output_value = round_function(input_value, round_key_value);
        output_value.to_be_bytes().to_vec()
    }
}