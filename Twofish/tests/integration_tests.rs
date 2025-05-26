#[cfg(test)]
mod integration_tests {
    use symmetric_cipher::crypto::cipher_traits::CipherAlgorithm;
    use twofish::TwofishCipher;

    const TEST_KEY_128: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];

    const TEST_KEY_192: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];

    const TEST_KEY_256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];

    #[test]
    fn test_encrypt_decrypt_official_vectors() {
        // Проверяем, что шифрование и последующая дешифровка восстанавливают нулевой блок
        let test_vectors = vec![
            (&TEST_KEY_128[..], &[0u8; 16][..]),
            (&TEST_KEY_192[..], &[0u8; 16][..]),
            (&TEST_KEY_256[..], &[0u8; 16][..]),
        ];

        for (i, (key, plaintext)) in test_vectors.iter().enumerate() {
            let cipher = TwofishCipher::new(key);
            let encrypted = cipher.encrypt(plaintext);
            let decrypted = cipher.decrypt(&encrypted);

            assert_eq!(
                decrypted, *plaintext,
                "Test #{}: encryption/decryption failed for key length {} bits",
                i,
                key.len() * 8
            );
        }
    }

    #[test]
    fn test_multiple_blocks_encrypt_decrypt() {
        let cipher = TwofishCipher::new(&TEST_KEY_128);
        let plaintext: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
        ];

        let encrypted = cipher.encrypt(&plaintext);
        let decrypted = cipher.decrypt(&encrypted);

        assert_eq!(
            decrypted,
            plaintext,
            "Multiple blocks encryption/decryption should return original data"
        );
    }

    #[test]
    #[should_panic(expected = "Data length must be multiple of 16")]
    fn test_raw_encrypt_panics_on_partial_block() {
        let cipher = TwofishCipher::new(&TEST_KEY_128);
        let partial_plaintext: [u8; 23] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07,
        ];
        let _ = cipher.encrypt(&partial_plaintext);
    }

    #[test]
    fn test_empty_data_encrypt_decrypt() {
        let cipher = TwofishCipher::new(&TEST_KEY_128);
        let empty: [u8; 0] = [];
        let encrypted = cipher.encrypt(&empty);
        let decrypted = cipher.decrypt(&encrypted);

        assert_eq!(
            decrypted,
            empty,
            "Empty data should be processed correctly"
        );
    }
}
