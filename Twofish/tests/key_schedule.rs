#[cfg(test)]
mod tests {
    use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;
    use symmetric_cipher::crypto::key_expansion::KeyExpansion;
    use Twofish::crypto::key_schedule::expand_key;
    use super::*;
    use Twofish::crypto::twofish::Twofish;

    // Вспомогательная функция для проверки структуры подключей
    fn check_round_keys_structure(round_keys: &[Vec<u8>]) {
        // В Twofish должно быть 40 подключей (для 16 раундов + начальное и конечное отбеливание)
        assert_eq!(round_keys.len(), 40, "Должно быть 40 подключей");

        // Каждый подключ должен быть длиной 4 байта (32 бита)
        for (i, key) in round_keys.iter().enumerate() {
            assert_eq!(key.len(), 4, "Подключ {} должен быть 4 байта", i);
        }
    }

    #[test]
    fn test_key_expansion_128bit() {
        // Проверка для 128-битного ключа
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        ];

        let twofish = Twofish::new(&key);
        let round_keys = twofish.generate_round_keys(&key);

        check_round_keys_structure(&round_keys);

        // Проверка известных значений первых подключей для 128-битного ключа
        // Значения взяты из спецификации Twofish
        assert_eq!(
            round_keys[0],
            vec![0x52, 0xB7, 0x5E, 0x01],
            "Первый подключ не соответствует ожидаемому"
        );
        assert_eq!(
            round_keys[1],
            vec![0x5B, 0xFF, 0xD2, 0x80],
            "Второй подключ не соответствует ожидаемому"
        );
    }

    #[test]
    fn test_key_expansion_192bit() {
        // Проверка для 192-битного ключа
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        ];

        let twofish = Twofish::new(&key);
        let round_keys = twofish.generate_round_keys(&key);

        check_round_keys_structure(&round_keys);

        // Проверка известных значений для 192-битного ключа
        assert_eq!(
            round_keys[0],
            vec![0x52, 0xB7, 0x5E, 0x01],
            "Первый подключ не соответствует ожидаемому"
        );
    }

    #[test]
    fn test_key_expansion_256bit() {
        // Проверка для 256-битного ключа
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        ];

        let twofish = Twofish::new(&key);
        let round_keys = twofish.generate_round_keys(&key);

        check_round_keys_structure(&round_keys);

        // Проверка известных значений для 256-битного ключа
        assert_eq!(
            round_keys[0],
            vec![0x52, 0xB7, 0x5E, 0x01],
            "Первый подключ не соответствует ожидаемому"
        );
    }

    #[test]
    fn test_expand_key_function() {
        // Проверка функции expand_key напрямую
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        ];

        let expanded_keys = expand_key(&key);

        // Проверка, что у нас 16 подключей по 64 бита
        assert_eq!(expanded_keys.len(), 16, "Должно быть 16 64-битных подключей");

        // Проверка первого подключа (если есть известное значение)
        assert_eq!(
            expanded_keys[0],
            0x52B75E015BFFD280,
            "Первый расширенный подключ не соответствует ожидаемому"
        );
    }

    #[test]
    fn test_invalid_key_size() {
        // Проверка обработки недопустимого размера ключа
        let invalid_key = [0x01, 0x02, 0x03]; // Слишком короткий ключ

        let twofish = Twofish::new(&[0; 16]); // Валидная инициализация
        let round_keys = twofish.generate_round_keys(&invalid_key);

        // Должен быть пустой результат или обработка ошибки
        assert!(round_keys.is_empty(), "Для неправильного ключа должен быть пустой результат");
    }

    #[test]
    fn test_encryption_transformation() {
        // Проверка трансформации шифрования
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        ];

        let twofish = Twofish::new(&key);

        // Создаем один подключ
        let round_key = vec![0x52, 0xB7, 0x5E, 0x01];

        // Блок для шифрования
        let block = [0; 16]; // Нулевой блок

        // Применение трансформации
        let transformed = twofish.transform(&block, &round_key);

        // Проверка размера результата
        assert_eq!(transformed.len(), 16, "Результат должен быть 16 байт");

        // Проверка, что преобразование изменило блок
        assert_ne!(transformed, block, "Трансформация должна изменить блок");
    }
}