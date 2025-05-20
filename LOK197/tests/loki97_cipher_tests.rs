// tests/loki97_cipher_tests.rs

use LOK197::crypto::loki97::Loki97Cipher;
use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds,
};

#[test]
fn test_block_size_is_correct() {
    let cipher = Loki97Cipher::new(&[0u8; 16]);
    assert_eq!(cipher.block_size(), 8);
}

#[test]
fn test_export_round_keys_len() {
    let cipher = Loki97Cipher::new(&[0u8; 16]);
    let rk = cipher.export_round_keys().unwrap();
    assert_eq!(rk.len(), 16 * 8);
}

#[test]
fn test_set_key_with_rounds_does_not_panic() {
    let mut cipher = Loki97Cipher::new(&[0u8; 16]);
    cipher.set_key_with_rounds(&[1u8; 16 * 8]);
}

#[test]
fn test_set_key_valid_key() {
    let mut cipher = Loki97Cipher::new(&[0u8; 16]);
    assert!(cipher.set_key(&[1u8; 16]).is_ok());
}

#[test]
fn test_encrypt_decrypt_block_round_keys() {
    let cipher = Loki97Cipher::new(&[0u8; 32]);
    let rk = cipher.export_round_keys().unwrap();

    let plaintext = [0,1,2,3,4,5,6,7];
    let ciphertext = cipher.encrypt_block(&plaintext, &rk);
    let decrypted  = cipher.decrypt_block(&ciphertext, &rk);

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_full_data() {
    let cipher = Loki97Cipher::new(&[0x10u8; 32]);
    let plaintext = vec![0xAAu8; 16];
    let ciphertext = cipher.encrypt(&plaintext);
    let decrypted  = cipher.decrypt(&ciphertext);

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_different_keys_produce_different_ciphertexts() {
    let c1 = Loki97Cipher::new(&[0u8; 32]);
    let c2 = Loki97Cipher::new(&[1u8; 32]);
    let plaintext = [1u8; 8];

    let ct1 = c1.encrypt_block(&plaintext, &c1.export_round_keys().unwrap());
    let ct2 = c2.encrypt_block(&plaintext, &c2.export_round_keys().unwrap());

    assert_ne!(ct1, ct2);
}
