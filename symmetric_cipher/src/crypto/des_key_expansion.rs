use crate::crypto::des_tables::{PC1, PC2};
use crate::crypto::key_expansion::KeyExpansion;
use crate::crypto::utils::{shift_bits_little_endian, bytes_to_bits, bits_to_bytes};
use bitvec::prelude::BitVec;

const SHIFT_BITS: [usize; 16] = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1,
];

pub struct DesKeyExpansion;

impl KeyExpansion for DesKeyExpansion {
    fn generate_round_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(key.len(), 8, "DES key must be 8 bytes, it is in des generate round keys");

        // 1) PC-1: переставляем биты 64-битного ключа → 56 бит → 7 байт
        let permuted = shift_bits_little_endian(key, &PC1, true, 1);
        let bits = bytes_to_bits(&permuted); // BitVec длины 56

        // 2) Разбиваем на C и D (по 28 бит)
        let mut c = bits.iter().by_vals().take(28).collect::<BitVec>();
        let mut d = bits.iter().by_vals().skip(28).take(28).collect::<BitVec>();

        // 3) Для каждого раунда: сдвигаем C и D, объединяем, применяем PC-2
        let mut round_keys = Vec::with_capacity(16);
        for &shift in &SHIFT_BITS {
            c.rotate_left(shift);
            d.rotate_left(shift);

            let mut cd = BitVec::with_capacity(56);
            cd.extend(c.iter().by_vals());
            cd.extend(d.iter().by_vals());

            let cd_bytes = bits_to_bytes(&cd);
            let subkey = shift_bits_little_endian(&cd_bytes, &PC2, true, 1);
            round_keys.push(subkey);
        }

        round_keys
    }
}
