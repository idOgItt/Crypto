#[cfg(test)]
mod tests {
    use symmetric_cipher::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds};
    use twofish::crypto::twofish::Twofish;

    // Известные тестовые векторы из спецификации Twofish
    const TEST_KEY_128: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];

    const TEST_PLAINTEXT_1: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    const TEST_CIPHERTEXT_1: [u8; 16] = [
        0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
        0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A
    ];

    const TEST_KEY_192: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    ];

    const TEST_PLAINTEXT_2: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    const TEST_CIPHERTEXT_2: [u8; 16] = [
        0x0C, 0xFD, 0x8C, 0x9E, 0x0F, 0xC5, 0x96, 0x64,
        0x14, 0x3C, 0x5F, 0x2E, 0xDB, 0x5A, 0x9B, 0x17
    ];

    const TEST_KEY_256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ];

    const TEST_PLAINTEXT_3: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ];

    const TEST_CIPHERTEXT_3: [u8; 16] = [
        0x37, 0x52, 0x7B, 0xE0, 0x05, 0x23, 0x34, 0xB8,
        0x9F, 0x0C, 0xFC, 0xCA, 0xE8, 0x7C, 0xFA, 0x20
    ];

    #[test]
    fn test_block_size() {
        let cipher = Twofish::new(&TEST_KEY_128);
        assert_eq!(cipher.block_size(), 16); // 128 бит = 16 байт
    }
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Произвольный ключ и текст
        let key = [
            0x42, 0x1A, 0x7B, 0x3D, 0x5E, 0x16, 0x8F, 0x24,
            0x91, 0xC2, 0xF3, 0x0E, 0xDA, 0x46, 0xB5, 0x7C
        ];
        let plaintext = [
            0x39, 0x24, 0x56, 0x78, 0xFA, 0xBC, 0xDE, 0xF0,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
        ];

        let cipher = Twofish::new(&key);
        let encrypted = cipher.encrypt(&plaintext);
        let decrypted = cipher.decrypt(&encrypted);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_size() {
        let invalid_key = [0x00, 0x01, 0x02, 0x03]; // Слишком короткий ключ
        let mut cipher = Twofish::new(&[0; 16]); // Создаем с валидным ключом

        // Проверяем, что set_key возвращает ошибку
        assert!(cipher.set_key(&invalid_key).is_err());
    }

    #[test]
    fn test_set_key() {
        let mut cipher = Twofish::new(&[0; 16]); // Инициализируем с нулевым ключом
        let _encrypted_first = cipher.encrypt(&TEST_PLAINTEXT_1);
        // Меняем ключ
        cipher.set_key(&TEST_KEY_128).unwrap();

        // Проверяем, что шифрование с новым ключом работает правильно
        let encrypted = cipher.encrypt(&TEST_PLAINTEXT_1);
        assert_ne!(encrypted, _encrypted_first);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_blocks() {
        let cipher = Twofish::new(&TEST_KEY_128);
        // 48 байт = 3 блока по 16 байт
        let plaintext = vec![0xAAu8; 48];
        let ciphertext = cipher.encrypt(&plaintext);
        let decrypted = cipher.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let c1 = Twofish::new(&[0u8; 32]);
        let c2 = Twofish::new(&[1u8; 32]);
        let plaintext = [1u8; 16];

        let ct1 = c1.encrypt(&plaintext);
        let ct2 = c2.encrypt(&plaintext);

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_export_round_keys() {
        let cipher = Twofish::new(&TEST_KEY_128);
        let round_keys = cipher.export_round_keys();
        assert!(round_keys.is_some());
        let keys = round_keys.unwrap();
        // 40 раундовых ключей по 4 байта = 160 байт
        assert_eq!(keys.len(), 160);
    }

    #[test]
    fn test_encrypt_with_rounds() {
        let cipher = Twofish::new(&TEST_KEY_128);
        let plaintext = [0u8; 16];

        // Тестируем с разным количеством раундов
        for rounds in 1..=16 {
            let encrypted = cipher.encrypt_with_rounds(&plaintext, rounds);
            assert_eq!(encrypted.len(), 16);

            // Проверяем, что можем расшифровать
            let decrypted = cipher.decrypt_with_rounds(&encrypted, rounds);
            assert_eq!(decrypted, plaintext);
        }
    }
}