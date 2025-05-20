use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::twofish::Twofish;
use symmetric_cipher::crypto::key_expansion::KeyExpansion;
use crate::crypto::mds::mds_multiply;
use crate::crypto::utils::{rotate_left, rotate_right};
use crate::crypto::sboxes::{q0, q1};

/// Функция h twofish
fn h(x: u32, key_bytes: &[u8], offset: usize) -> u32 {
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

/// Расширение ключа для Twofish
pub fn expand_key(master_key: &[u8]) -> Vec<u32> {
    if master_key.len() != 16 && master_key.len() != 24 && master_key.len() != 32 {
        return Vec::new();
    }

    // 40 подключей, по одному на каждое 32-битное слово
    let mut round_keys = Vec::with_capacity(40);

    // Константа для расширения ключа
    const P: u32 = 0x01010101;

    // Расчет Me и Mo
    let mut me = [0u32; 4];
    let mut mo = [0u32; 4];

    for i in 0..master_key.len() / 8 {
        me[i] = (master_key[8*i] as u32) | ((master_key[8*i + 1] as u32) << 8) |
            ((master_key[8*i + 2] as u32) << 16) | ((master_key[8*i + 3] as u32) << 24);
        mo[i] = (master_key[8*i + 4] as u32) | ((master_key[8*i + 5] as u32) << 8) |
            ((master_key[8*i + 6] as u32) << 16) | ((master_key[8*i + 7] as u32) << 24);
    }

    // Расчет подключей
    for i in 0..20 {
        let a = h(2 * i as u32 * P, master_key, 0);
        let b = rotate_left(h((2 * i + 1) as u32 * P, master_key, 4), 8);

        round_keys.push(a.wrapping_add(b));
        round_keys.push(rotate_left(a.wrapping_add(b.wrapping_mul(2)), 9));
    }

    round_keys
}

impl KeyExpansion for Twofish {
    fn generate_round_keys(&self, master_key: &[u8]) -> Vec<Vec<u8>> {
        if master_key.len() != 16 && master_key.len() != 24 && master_key.len() != 32 {
            return Vec::new();
        }

        let round_keys = expand_key(master_key);

        // Преобразуем u32 в Vec<u8>
        let mut result = Vec::with_capacity(round_keys.len());

        for key in round_keys {
            let k = vec![
                (key >> 24) as u8,
                (key >> 16) as u8,
                (key >> 8) as u8,
                key as u8
            ];
            result.push(k);
        }

        result
    }
}

impl EncryptionTransformation for Twofish {
    fn transform(&self, plaintext_block: &[u8], round_key: &[u8]) -> Vec<u8> {
        if plaintext_block.len() != 16 || round_key.len() != 4 {
            return Vec::new();
        }

        // Разбиваем блок на 4 слова по 32 бита (младший байт справа)
        let mut block = [0u32; 4];
        for i in 0..4 {
            block[i] = ((plaintext_block[4*i] as u32) << 24) |
                ((plaintext_block[4*i + 1] as u32) << 16) |
                ((plaintext_block[4*i + 2] as u32) << 8) |
                (plaintext_block[4*i + 3] as u32);
        }

        // Преобразуем ключ раунда в 32-битное слово
        let k = ((round_key[0] as u32) << 24) |
            ((round_key[1] as u32) << 16) |
            ((round_key[2] as u32) << 8) |
            (round_key[3] as u32);

        // Выполняем одно раундовое преобразование (упрощенно)
        block[0] ^= k;

        // Преобразуем обратно в байты
        let mut result = Vec::with_capacity(16);
        for word in block {
            result.push((word >> 24) as u8);
            result.push((word >> 16) as u8);
            result.push((word >> 8) as u8);
            result.push(word as u8);
        }

        result
    }
}