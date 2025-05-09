use rijndael::gf::arithmetic::Poly;
use rijndael::{
    rijndael::cipher::{aes_encrypt_block, aes_decrypt_block},
    rijndael::key_schedule::expand_key,
};

/// Вспомогалка: строит Poly из среза битов (0 или 1)
fn poly_from_bits(bits: &[u8]) -> Poly {
    bits.iter().map(|&b| b != 0).collect()
}

/// Вспомогалка: преобразует массив байт в [u8; 16]
fn block_from_bytes(bytes: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block.copy_from_slice(bytes);
    block
}

#[test]
fn test_aes128_nist_vector() {
    // Параметры из FIPS-197, пример AES-128
    let key = [
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
    ];
    let plaintext = block_from_bytes(&[
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34,
    ]);
    let expected_cipher = block_from_bytes(&[
        0x39, 0x25, 0x84, 0x1d,
        0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97,
        0x19, 0x6a, 0x0b, 0x32,
    ]);

    // Стандартный неприводимый полином AES: x⁸ + x⁴ + x³ + x + 1
    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]);

    let round_keys = expand_key(&key, &poly);
    let cipher = aes_encrypt_block(&plaintext, &round_keys, &poly);
    assert_eq!(cipher, expected_cipher, "AES-128 encryption mismatch");

    let decrypted = aes_decrypt_block(&cipher, &round_keys, &poly);
    assert_eq!(decrypted, plaintext, "AES-128 decryption failed to invert");
}

#[test]
fn test_aes192_known_vector() {
    // Пример AES-192 из NIST
    let key = [
        0x8e, 0x73, 0xb0, 0xf7,
        0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2,
        0x52, 0x2c, 0x6b, 0x7b,
    ];
    let plaintext = block_from_bytes(&[
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a,
    ]);
    let expected_cipher = block_from_bytes(&[
        0xbd, 0x33, 0x4f, 0x1d,
        0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14,
        0x57, 0x1f, 0xa5, 0xcc,
    ]);

    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]);
    let round_keys = expand_key(&key, &poly);
    let cipher = aes_encrypt_block(&plaintext, &round_keys, &poly);
    assert_eq!(cipher, expected_cipher, "AES-192 encryption mismatch");

    let decrypted = aes_decrypt_block(&cipher, &round_keys, &poly);
    assert_eq!(decrypted, plaintext, "AES-192 decryption failed");
}

#[test]
fn test_aes256_known_vector() {
    // Пример AES-256 из NIST
    let key = [
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,
        0x09, 0x14, 0xdf, 0xf4,
    ];
    let plaintext = block_from_bytes(&[
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a,
    ]);
    let expected_cipher = block_from_bytes(&[
        0xf3, 0xee, 0xd1, 0xbd,
        0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e,
        0x3d, 0xb1, 0x81, 0xf8,
    ]);

    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]);
    let round_keys = expand_key(&key, &poly);
    let cipher = aes_encrypt_block(&plaintext, &round_keys, &poly);
    assert_eq!(cipher, expected_cipher, "AES-256 encryption mismatch");

    let decrypted = aes_decrypt_block(&cipher, &round_keys, &poly);
    assert_eq!(decrypted, plaintext, "AES-256 decryption failed");
}

#[test]
fn test_encrypt_decrypt_random() {
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;

    // Фиксированный сид для воспроизводимости
    let mut rng = StdRng::seed_from_u64(0xdead_beef);
    let mut key = [0u8; 32];
    let mut block = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut block);

    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]);
    let round_keys = expand_key(&key, &poly);
    let cipher = aes_encrypt_block(&block, &round_keys, &poly);
    let decrypted = aes_decrypt_block(&cipher, &round_keys, &poly);
    assert_eq!(decrypted, block, "Random encrypt/decrypt failed");
}
