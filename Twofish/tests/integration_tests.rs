#[cfg(test)]
mod integration_tests {
    use symmetric_cipher::crypto::cipher_traits::CipherAlgorithm;
    use twofish::TwofishCipher;
    const TEST_KEY_128: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];

    const TEST_KEY_192: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    ];

    const TEST_KEY_256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ];

    struct TestVector {
        key: &'static [u8],
        plaintext: &'static [u8],
        ciphertext: &'static [u8],
    }

    #[test]
    fn test_official_vectors() {
        let test_vectors = vec![
            // 128-битный ключ
            TestVector {
                key: &TEST_KEY_128,
                plaintext: &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
                ciphertext: &[
                    0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
                    0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A
                ],
            },
            TestVector {
                key: &TEST_KEY_192,
                plaintext: &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
                ciphertext: &[
                    0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44,
                    0x8F, 0x28, 0x9D, 0x02, 0xB9, 0x04, 0x1F, 0xDB
                ],
            },
            TestVector {
                key: &TEST_KEY_256,
                plaintext: &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ],
                ciphertext: &[
                    0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75,
                    0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05
                ],
            },
        ];

        for (i, test) in test_vectors.iter().enumerate() {
            let cipher = TwofishCipher::new(test.key);

            let encrypted = cipher.encrypt(test.plaintext);
            assert_eq!(
                encrypted, test.ciphertext,
                "Тест #{}: Шифрование не соответствует ожидаемому результату", i
            );

            let decrypted = cipher.decrypt(test.ciphertext);
            assert_eq!(
                decrypted, test.plaintext,
                "Тест #{}: Дешифрование не соответствует ожидаемому результату", i
            );
        }
    }

    #[test]
    fn test_multiple_blocks() {
        // Проверка шифрования/дешифрования нескольких блоков данных
        let cipher = TwofishCipher::new(&TEST_KEY_128);

        // Данные длиной в несколько блоков
        let plaintext = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90
        ];

        let encrypted = cipher.encrypt(&plaintext);
        let decrypted = cipher.decrypt(&encrypted);

        assert_eq!(
            decrypted, plaintext,
            "Шифрование и дешифрование нескольких блоков не совпадает с оригиналом"
        );
    }

    #[test]
    fn test_padding() {
        // Проверка, что данные, не кратные блоку, корректно обрабатываются
        let cipher = TwofishCipher::new(&TEST_KEY_128);

        // Данные не кратны размеру блока (16 байт)
        let plaintext = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07
        ];

        let encrypted = cipher.encrypt(&plaintext);

        // Результат должен быть кратен размеру блока (16 байт)
        assert_eq!(
            encrypted.len() % 16, 0,
            "Размер зашифрованных данных должен быть кратен размеру блока"
        );

        let decrypted = cipher.decrypt(&encrypted);

        // После дешифрования должны получить оригинальные данные
        assert_eq!(
            decrypted.len(), plaintext.len(),
            "Размер дешифрованных данных должен соответствовать оригиналу"
        );

        assert_eq!(
            decrypted, plaintext,
            "Дешифрованные данные должны соответствовать оригиналу"
        );
    }

    #[test]
    fn test_empty_data() {
        // Проверка обработки пустых данных
        let cipher = TwofishCipher::new(&TEST_KEY_128);

        let empty_data: [u8; 0] = [];

        let encrypted = cipher.encrypt(&empty_data);
        let decrypted = cipher.decrypt(&encrypted);

        assert_eq!(
            decrypted, empty_data,
            "Пустые данные должны быть корректно обработаны"
        );
    }
}