// tests/key_schedule.rs

use std::array::from_fn;
use twofish::TwofishCipher;
use twofish::crypto::key_schedule::expand_key;
use twofish::crypto::twofish::Twofish;

use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;
use symmetric_cipher::crypto::key_expansion::KeyExpansion;

/// Вспомогательная функция для проверки структуры подключей
fn check_round_keys_structure(round_keys: &[Vec<u8>]) {
    // В Twofish должно быть 40 подключей (для 16 раундов + pre-/post-whitening)
    assert_eq!(round_keys.len(), 40, "Должно быть 40 подключей");
    for (i, key) in round_keys.iter().enumerate() {
        assert_eq!(key.len(), 4, "Подключ {} должен быть 4 байта", i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_expansion_128bit() {
        // Генерируем ключ 0x00..0x0F
        let key: [u8; 16] = from_fn(|i| i as u8);
        let twofish = Twofish::new(&key);
        let round_keys = twofish.generate_round_keys(&key);

        check_round_keys_structure(&round_keys);

        // Первые два подключа для 128-битного ключа
        assert_eq!(
            round_keys[0],
            vec![0xD9, 0x3C, 0x53, 0x95],
            "Первый подключ не соответствует результату функции"
        );
        assert_eq!(
            round_keys[1],
            vec![0xDF, 0xE0, 0xBF, 0x0E],
            "Второй подключ не соответствует результату функции"
        );
    }

    #[test]
    fn test_key_expansion_192bit() {
        // Генерируем ключ 0x00..0x17
        let key: [u8; 24] = from_fn(|i| i as u8);
        let twofish = Twofish::new(&key);
        let round_keys = twofish.generate_round_keys(&key);

        check_round_keys_structure(&round_keys);

        // Первый подключ для 192-битного ключа
        assert_eq!(
            round_keys[0],
            vec![0x46, 0x0D, 0x9A, 0x3A],
            "Первый подключ для 192-битного ключа некорректен"
        );
    }

    #[test]
    fn test_key_expansion_256bit() {
        // Генерируем ключ 0x00..0x1F
        let key: [u8; 32] = from_fn(|i| i as u8);
        let twofish = Twofish::new(&key);
        let round_keys = twofish.generate_round_keys(&key);

        check_round_keys_structure(&round_keys);

        // Первый подключ для 256-битного ключа
        assert_eq!(
            round_keys[0],
            vec![0xC0, 0xBB, 0xD1, 0xE6],
            "Первый подключ для 256-битного ключа некорректен"
        );
    }

    #[test]
    fn test_expand_key_function() {
        // Проверка функции expand_key напрямую
        let key: [u8; 16] = from_fn(|i| i as u8);
        let expanded = expand_key(&key);

        // Должно быть ровно 40 32-битных слов
        assert_eq!(expanded.len(), 40, "Должно быть 40 расширенных подключей");

        // Первые два слова в виде u32
        assert_eq!(
            expanded[0],
            0xD93C5395,
            "Первое слово expand_key некорректно"
        );
        assert_eq!(
            expanded[1],
            0xDFE0BF0E,
            "Второе слово expand_key некорректно"
        );
    }

    #[test]
    fn test_invalid_key_size() {
        // Недопустимый ключ длиной 3 байта
        let invalid: [u8; 3] = [0x00; 3];
        // Для инициализации Twofish используем валидный 128-битный ключ
        let valid_key: [u8; 16] = from_fn(|i| i as u8);
        let twofish = Twofish::new(&valid_key);
        let rk = twofish.generate_round_keys(&invalid);
        assert!(rk.is_empty(), "Для неверного размера ключа результат должен быть пустым");
    }

    #[test]
    fn test_encryption_transformation() {
        let key: [u8; 16] = from_fn(|i| i as u8);
        let twofish = Twofish::new(&key);
        let round_key = vec![0xD9, 0x3C, 0x53, 0x95];
        let block = [0u8; 16];
        let out = twofish.transform(&block, &round_key);

        assert_eq!(out.len(), 16, "Результат должен быть 16 байт");
        assert_ne!(out, block, "Трансформация должна что-то поменять");
    }
}
