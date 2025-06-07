use crate::crypto::gf256::gf_mul;

/// Преобразование MDS-матрицы над GF(2^8) для 32-битного слова.
/// Смешивает 4 байта по MDS-матрице Twofish.
pub fn mds_multiply(word: u32) -> u32 {
    let z0 = (word >> 24) as u8;
    let z1 = (word >> 16) as u8;
    let z2 = (word >> 8) as u8;
    let z3 = word as u8;

    // MDS-матрица Twofish
    // | 01 EF 5B 5B |
    // | 5B EF EF 01 |
    // | EF 5B 01 EF |
    // | EF 01 EF 5B |

    // Вычисляем новые значения байтов
    let y0 = gf_mul(z0, 0x01) ^ gf_mul(z1, 0xEF) ^ gf_mul(z2, 0x5B) ^ gf_mul(z3, 0x5B);
    let y1 = gf_mul(z0, 0x5B) ^ gf_mul(z1, 0xEF) ^ gf_mul(z2, 0xEF) ^ gf_mul(z3, 0x01);
    let y2 = gf_mul(z0, 0xEF) ^ gf_mul(z1, 0x5B) ^ gf_mul(z2, 0x01) ^ gf_mul(z3, 0xEF);
    let y3 = gf_mul(z0, 0xEF) ^ gf_mul(z1, 0x01) ^ gf_mul(z2, 0xEF) ^ gf_mul(z3, 0x5B);

    ((y0 as u32) << 24) | ((y1 as u32) << 16) | ((y2 as u32) << 8) | (y3 as u32)
}
