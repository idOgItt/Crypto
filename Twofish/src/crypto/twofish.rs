use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm,
    SymmetricCipher,
    SymmetricCipherWithRounds,
};
use crate::crypto::key_schedule::expand_key;
use crate::crypto::utils::{rotate_left, rotate_right};
use crate::crypto::pht::pht;
use crate::crypto::mds::mds_multiply;
use crate::crypto::sboxes::{q0, q1};

#[derive(Clone)]
pub struct Twofish {
    /// 40 подключей, полученных из основного ключа
    round_keys: Vec<u32>,
}

impl Twofish {
    /// Create a new cipher, deriving subkeys from the master key.
    pub fn new(master_key: &[u8]) -> Self {
        let round_keys = if master_key.len() == 16 || master_key.len() == 24 || master_key.len() == 32 {
            expand_key(master_key)
        } else {
            Vec::new()
        };

        Twofish { round_keys }
    }

    // Функция h, используемая в Twofish
    fn h(&self, x: u32, key_bytes: &[u8], offset: usize) -> u32 {
        let b0 = (x & 0xFF) as u8;
        let b1 = ((x >> 8) & 0xFF) as u8;
        let b2 = ((x >> 16) & 0xFF) as u8;
        let b3 = ((x >> 24) & 0xFF) as u8;

        let mut y0 = q1(q0(q0(b0) ^ key_bytes[offset]) ^ key_bytes[offset + 8]);
        let mut y1 = q0(q0(q1(b1) ^ key_bytes[offset + 1]) ^ key_bytes[offset + 9]);
        let mut y2 = q1(q1(q0(b2) ^ key_bytes[offset + 2]) ^ key_bytes[offset + 10]);
        let mut y3 = q0(q1(q1(b3) ^ key_bytes[offset + 3]) ^ key_bytes[offset + 11]);

        // Если ключ длиннее 128 бит
        if key_bytes.len() >= 24 {
            y0 = q1(y0 ^ key_bytes[offset + 16]);
            y1 = q0(y1 ^ key_bytes[offset + 17]);
            y2 = q1(y2 ^ key_bytes[offset + 18]);
            y3 = q0(y3 ^ key_bytes[offset + 19]);

            // Если ключ длиннее 192 бит
            if key_bytes.len() >= 32 {
                y0 = q0(y0 ^ key_bytes[offset + 24]);
                y1 = q1(y1 ^ key_bytes[offset + 25]);
                y2 = q0(y2 ^ key_bytes[offset + 26]);
                y3 = q1(y3 ^ key_bytes[offset + 27]);
            }
        }

        // MDS-умножение
        let word = ((y0 as u32) << 24) | ((y1 as u32) << 16) | ((y2 as u32) << 8) | (y3 as u32);
        mds_multiply(word)
    }

    // Функция F, используемая в раундах Twofish
    fn f_function(&self, r: u32, a: u32, b: u32, key_bytes: &[u8]) -> (u32, u32) {
        let t0 = self.h(a, key_bytes, 0);
        let t1 = self.h(rotate_left(b, 8), key_bytes, 4);

        let (p0, p1) = pht(t0, t1);

        let s0 = p0.wrapping_add(self.round_keys[(2 * r) as usize]);
        let s1 = p1.wrapping_add(self.round_keys[(2 * r + 1) as usize]);

        (s0, s1)
    }

    /// Encrypt one 128-bit block via 16-round Feistel.
    fn feistel_encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        if self.round_keys.len() < 40 {
            return [0; 16];
        }

        // Разбиваем блок на 4 слова по 32 бита
        let mut a = ((block[0] as u32) << 24) | ((block[1] as u32) << 16) |
            ((block[2] as u32) << 8) | (block[3] as u32);
        let mut b = ((block[4] as u32) << 24) | ((block[5] as u32) << 16) |
            ((block[6] as u32) << 8) | (block[7] as u32);
        let mut c = ((block[8] as u32) << 24) | ((block[9] as u32) << 16) |
            ((block[10] as u32) << 8) | (block[11] as u32);
        let mut d = ((block[12] as u32) << 24) | ((block[13] as u32) << 16) |
            ((block[14] as u32) << 8) | (block[15] as u32);

        // Входное отбеливание
        a ^= self.round_keys[0];
        b ^= self.round_keys[1];
        c ^= self.round_keys[2];
        d ^= self.round_keys[3];

        // Создаем ключевые байты для функции h
        let mut key_bytes = Vec::with_capacity(32);
        // В реальной реализации здесь нужно добавить байты из Me и Mo
        // Для простоты, используем первые байты ключа
        for i in 0..32 {
            key_bytes.push(i as u8);
        }

        // 16 раундов шифрования
        for r in 0..16 {
            let (f0, f1) = self.f_function(r, a, b, &key_bytes);

            // Обновляем значения
            let temp = c;
            c = rotate_right(a ^ f0, 1);
            a = b;
            b = rotate_right(temp ^ f1, 1);

            // Меняем c и d местами (кроме последнего раунда)
            if r < 15 {
                let temp = c;
                c = d;
                d = temp;
            }
        }

        // Выходное отбеливание
        a ^= self.round_keys[4];
        b ^= self.round_keys[5];
        c ^= self.round_keys[6];
        d ^= self.round_keys[7];

        // Собираем блок обратно
        let mut result = [0u8; 16];
        result[0] = (a >> 24) as u8;
        result[1] = (a >> 16) as u8;
        result[2] = (a >> 8) as u8;
        result[3] = a as u8;
        result[4] = (b >> 24) as u8;
        result[5] = (b >> 16) as u8;
        result[6] = (b >> 8) as u8;
        result[7] = b as u8;
        result[8] = (c >> 24) as u8;
        result[9] = (c >> 16) as u8;
        result[10] = (c >> 8) as u8;
        result[11] = c as u8;
        result[12] = (d >> 24) as u8;
        result[13] = (d >> 16) as u8;
        result[14] = (d >> 8) as u8;
        result[15] = d as u8;

        result
    }

    /// Decrypt one 128-bit block via 16-round Feistel.
    fn feistel_decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        if self.round_keys.len() < 40 {
            return [0; 16];
        }

        // Разбиваем блок на 4 слова по 32 бита
        let mut a = ((block[0] as u32) << 24) | ((block[1] as u32) << 16) |
            ((block[2] as u32) << 8) | (block[3] as u32);
        let mut b = ((block[4] as u32) << 24) | ((block[5] as u32) << 16) |
            ((block[6] as u32) << 8) | (block[7] as u32);
        let mut c = ((block[8] as u32) << 24) | ((block[9] as u32) << 16) |
            ((block[10] as u32) << 8) | (block[11] as u32);
        let mut d = ((block[12] as u32) << 24) | ((block[13] as u32) << 16) |
            ((block[14] as u32) << 8) | (block[15] as u32);

        // Выходное отбеливание (в обратном порядке)
        a ^= self.round_keys[4];
        b ^= self.round_keys[5];
        c ^= self.round_keys[6];
        d ^= self.round_keys[7];

        // Создаем ключевые байты для функции h
        let mut key_bytes = Vec::with_capacity(32);
        // В реальной реализации здесь нужно добавить байты из Me и Mo
        // Для простоты, используем первые байты ключа
        for i in 0..32 {
            key_bytes.push(i as u8);
        }

        // 16 раундов дешифрования (в обратном порядке)
        for r in (0..16).rev() {
            let (f0, f1) = self.f_function(r, a, b, &key_bytes);

            // Если не первый раунд дешифрования, меняем c и d местами
            if r < 15 {
                let temp = c;
                c = d;
                d = temp;
            }

            // Обновляем значения (обратная операция шифрованию)
            let temp = a;
            a = rotate_left(c, 1) ^ f0;
            c = b;
            b = rotate_left(d, 1) ^ f1;
            d = temp;
        }

        // Входное отбеливание (в обратном порядке)
        a ^= self.round_keys[0];
        b ^= self.round_keys[1];
        c ^= self.round_keys[2];
        d ^= self.round_keys[3];

        // Собираем блок обратно
        let mut result = [0u8; 16];
        result[0] = (a >> 24) as u8;
        result[1] = (a >> 16) as u8;
        result[2] = (a >> 8) as u8;
        result[3] = a as u8;
        result[4] = (b >> 24) as u8;
        result[5] = (b >> 16) as u8;
        result[6] = (b >> 8) as u8;
        result[7] = b as u8;
        result[8] = (c >> 24) as u8;
        result[9] = (c >> 16) as u8;
        result[10] = (c >> 8) as u8;
        result[11] = c as u8;
        result[12] = (d >> 24) as u8;
        result[13] = (d >> 16) as u8;
        result[14] = (d >> 8) as u8;
        result[15] = d as u8;

        result
    }
}

impl CipherAlgorithm for Twofish {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        if self.round_keys.len() < 40 {
            return Vec::new();
        }

        let mut result = Vec::new();

        // Дополняем данные до кратности размеру блока (16 байт)
        let padding_size = 16 - (data.len() % 16);
        let mut padded_data = data.to_vec();
        for _ in 0..padding_size {
            padded_data.push(padding_size as u8);
        }

        // Шифруем блоки по 16 байт
        for chunk in padded_data.chunks(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            let encrypted_block = self.feistel_encrypt_block(&block);
            result.extend_from_slice(&encrypted_block);
        }

        result
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        if self.round_keys.len() < 40 || data.len() % 16 != 0 {
            return Vec::new();
        }

        let mut result = Vec::new();

        // Расшифровываем блоки по 16 байт
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            let decrypted_block = self.feistel_decrypt_block(&block);
            result.extend_from_slice(&decrypted_block);
        }

        // Удаляем padding
        if !result.is_empty() {
            let padding_size = result[result.len() - 1] as usize;
            if padding_size <= 16 && padding_size > 0 {
                // Проверяем, что padding корректный
                let valid_padding = result.len() >= padding_size &&
                    result[result.len() - padding_size..].iter()
                        .all(|&x| x == padding_size as u8);

                if valid_padding {
                    result.truncate(result.len() - padding_size);
                }
            }
        }

        result
    }
}

impl SymmetricCipher for Twofish {
    fn set_key(&mut self, master_key: &[u8]) -> Result<(), &'static str> {
        // Проверка длины ключа (128, 192 или 256 бит)
        if master_key.len() != 16 && master_key.len() != 24 && master_key.len() != 32 {
            return Err("Twofish supports only 128, 192, or 256-bit keys");
        }

        // Генерация подключей
        self.round_keys = expand_key(master_key);

        Ok(())
    }
}

impl SymmetricCipherWithRounds for Twofish {
    fn set_key_with_rounds(&mut self, raw: &[u8]) {
        if raw.len() == 16 || raw.len() == 24 || raw.len() == 32 {
            self.round_keys = expand_key(raw);
        }
    }

    fn encrypt_block(&self, block: &[u8], raw_round_keys: &[u8]) -> Vec<u8> {
        if block.len() != 16 || raw_round_keys.len() < 160 { // 40 * 4 = 160 байт для 40 u32 ключей
            return Vec::new();
        }

        // Создаем временный экземпляр с предоставленными ключами
        let mut temp_keys = Vec::with_capacity(40);
        for i in 0..40 {
            let key = ((raw_round_keys[4*i] as u32) << 24) |
                ((raw_round_keys[4*i + 1] as u32) << 16) |
                ((raw_round_keys[4*i + 2] as u32) << 8) |
                (raw_round_keys[4*i + 3] as u32);
            temp_keys.push(key);
        }

        let temp_cipher = Twofish { round_keys: temp_keys };

        // Преобразуем входной блок
        let mut block_array = [0u8; 16];
        block_array.copy_from_slice(block);

        // Шифруем и возвращаем результат
        let encrypted = temp_cipher.feistel_encrypt_block(&block_array);
        encrypted.to_vec()
    }

    fn decrypt_block(&self, block: &[u8], raw_round_keys: &[u8]) -> Vec<u8> {
        if block.len() != 16 || raw_round_keys.len() < 160 { // 40 * 4 = 160 байт для 40 u32 ключей
            return Vec::new();
        }

        // Создаем временный экземпляр с предоставленными ключами
        let mut temp_keys = Vec::with_capacity(40);
        for i in 0..40 {
            let key = ((raw_round_keys[4*i] as u32) << 24) |
                ((raw_round_keys[4*i + 1] as u32) << 16) |
                ((raw_round_keys[4*i + 2] as u32) << 8) |
                (raw_round_keys[4*i + 3] as u32);
            temp_keys.push(key);
        }

        let temp_cipher = Twofish { round_keys: temp_keys };

        // Преобразуем входной блок
        let mut block_array = [0u8; 16];
        block_array.copy_from_slice(block);

        // Дешифруем и возвращаем результат
        let decrypted = temp_cipher.feistel_decrypt_block(&block_array);
        decrypted.to_vec()
    }

    fn block_size(&self) -> usize {
        16 // 128 бит = 16 байт
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        if self.round_keys.len() < 40 {
            return None;
        }

        let mut result = Vec::with_capacity(160); // 40 * 4 = 160 байт для 40 u32 ключей

        for &key in &self.round_keys {
            result.push((key >> 24) as u8);
            result.push((key >> 16) as u8);
            result.push((key >> 8) as u8);
            result.push(key as u8);
        }

        Some(result)
    }
}