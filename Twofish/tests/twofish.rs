#[cfg(test)]
mod tests {
    use super::*;

    // Вспомогательная функция для создания 16-байтного блока из u128
    fn u128_to_block(value: u128) -> [u8; 16] {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[15 - i] = ((value >> (i * 8)) & 0xFF) as u8;
        }
        block
    }

    // Вспомогательная функция для преобразования блока в u128
    fn block_to_u128(block: &[u8; 16]) -> u128 {
        let mut result: u128 = 0;
        for (i, &byte) in block.iter().enumerate() {
            result |= (byte as u128) << ((15 - i) * 8);
        }
        result
    }

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
        0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44,
        0x8F, 0x28, 0x9D, 0x02, 0xB9, 0x04, 0x1F, 0xDB
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
        0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75,
        0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05
    ];

    #[test]
    fn test_block_size() {
        let cipher = Twofish::new(&TEST_KEY_128);
        assert_eq!(cipher.block_size(), 16); // 128 бит = 16 байт
    }

    #[test]
    fn test_encrypt_128bit_key() {
        let cipher = Twofish::new(&TEST_KEY_128);
        let encrypted = cipher.encrypt(&TEST_PLAINTEXT_1);
        assert_eq!(encrypted, TEST_CIPHERTEXT_1);
    }

    #[test]
    fn test_decrypt_128bit_key() {
        let cipher = Twofish::new(&TEST_KEY_128);
        let decrypted = cipher.decrypt(&TEST_CIPHERTEXT_1);
        assert_eq!(decrypted, TEST_PLAINTEXT_1);
    }

    #[test]
    fn test_encrypt_192bit_key() {
        let cipher = Twofish::new(&TEST_KEY_192);
        let encrypted = cipher.encrypt(&TEST_PLAINTEXT_2);
        assert_eq!(encrypted, TEST_CIPHERTEXT_2);
    }

    #[test]
    fn test_decrypt_192bit_key() {
        let cipher = Twofish::new(&TEST_KEY_192);
        let decrypted = cipher.decrypt(&TEST_CIPHERTEXT_2);
        assert_eq!(decrypted, TEST_PLAINTEXT_2);
    }

    #[test]
    fn test_encrypt_256bit_key() {
        let cipher = Twofish::new(&TEST_KEY_256);
        let encrypted = cipher.encrypt(&TEST_PLAINTEXT_3);
        assert_eq!(encrypted, TEST_CIPHERTEXT_3);
    }

    #[test]
    fn test_decrypt_256bit_key() {
        let cipher = Twofish::new(&TEST_KEY_256);
        let decrypted = cipher.decrypt(&TEST_CIPHERTEXT_3);
        assert_eq!(decrypted, TEST_PLAINTEXT_3);
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
    #[should_panic]
    fn test_invalid_key_size() {
        let invalid_key = [0x00, 0x01, 0x02, 0x03]; // Слишком короткий ключ
        let mut cipher = Twofish::new(&[0; 16]); // Создаем с валидным ключом

        // Ожидаем панику при попытке установить неверный ключ
        cipher.set_key(&invalid_key).unwrap();
    }

    #[test]
    fn test_set_key() {
        let mut cipher = Twofish::new(&[0; 16]); // Инициализируем с нулевым ключом

        // Меняем ключ
        cipher.set_key(&TEST_KEY_128).unwrap();

        // Проверяем, что шифрование с новым ключом работает правильно
        let encrypted = cipher.encrypt(&TEST_PLAINTEXT_1);
        assert_eq!(encrypted, TEST_CIPHERTEXT_1);
    }
}