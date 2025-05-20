#[cfg(test)]
mod tests {
    use twofish::crypto::gf256::gf_mul;
    use twofish::crypto::mds::mds_multiply;
    use super::*;
    

    // Функция для ручного вычисления MDS умножения (для тестов)
    fn manual_mds_multiply(input: u32) -> u32 {
        // MDS-матрица для Twofish:
        // | 01 EF 5B 5B |
        // | 5B EF EF 01 |
        // | EF 5B 01 EF |
        // | EF 01 EF 5B |

        let b0 = (input >> 24) as u8;
        let b1 = (input >> 16) as u8;
        let b2 = (input >> 8) as u8;
        let b3 = input as u8;

        let y0 = gf_mul(b0, 0x01) ^ gf_mul(b1, 0xEF) ^ gf_mul(b2, 0x5B) ^ gf_mul(b3, 0x5B);
        let y1 = gf_mul(b0, 0x5B) ^ gf_mul(b1, 0xEF) ^ gf_mul(b2, 0xEF) ^ gf_mul(b3, 0x01);
        let y2 = gf_mul(b0, 0xEF) ^ gf_mul(b1, 0x5B) ^ gf_mul(b2, 0x01) ^ gf_mul(b3, 0xEF);
        let y3 = gf_mul(b0, 0xEF) ^ gf_mul(b1, 0x01) ^ gf_mul(b2, 0xEF) ^ gf_mul(b3, 0x5B);

        ((y0 as u32) << 24) | ((y1 as u32) << 16) | ((y2 as u32) << 8) | (y3 as u32)
    }

    #[test]
    fn test_mds_multiply_zero() {
        // Умножение нуля на MDS-матрицу должно давать ноль
        assert_eq!(mds_multiply(0), 0);
    }

    #[test]
    fn test_mds_multiply_examples() {
        // Проверка нескольких примеров
        let test_values = [
            0x01020304,
            0x10203040,
            0xABCDEF12,
            0x12345678,
            0xFFFFFFFF
        ];

        for &val in &test_values {
            let expected = manual_mds_multiply(val);
            let result = mds_multiply(val);

            assert_eq!(
                result, expected,
                "MDS умножение для 0x{:08X}: ожидалось 0x{:08X}, получено 0x{:08X}",
                val, expected, result
            );
        }
    }

    #[test]
    fn test_mds_single_byte() {
        let cases = [
            (0x01000000, 0x015B_EFEF),
            (0x00010000, 0xEFEF_5B01),
            (0x00000100, 0x5BEF_01EF),
            (0x00000001, 0x5B01_EF5B),
        ];
        for (input, expected) in cases {
            assert_eq!(
                mds_multiply(input), expected,
                "Для 0x{:08X}: ожидалось 0x{:08X}, получено 0x{:08X}",
                input, expected, mds_multiply(input)
            );
        }
    }

    #[test]
    fn test_mds_specific_vectors() {
        let cases = [
            (0x00000000, 0x0000_0000),
            (0x01010101, 0xEE5A_5A5A),
            (0xFFFFFFFF, 0x1AD1_D1D1),
        ];
        for (input, expected) in cases {
            assert_eq!(
                mds_multiply(input), expected,
                "Для 0x{:08X}: ожидалось 0x{:08X}, получено 0x{:08X}",
                input, expected, mds_multiply(input)
            );
        }
    }

    #[test]
    fn test_mds_linearity() {
        // Проверка свойства линейности: M(A ⊕ B) = M(A) ⊕ M(B)
        let a = 0x12345678;
        let b = 0x87654321;

        let direct = mds_multiply(a ^ b);
        let separate = mds_multiply(a) ^ mds_multiply(b);

        assert_eq!(
            direct, separate,
            "Линейность MDS не соблюдается: M(A ⊕ B) ≠ M(A) ⊕ M(B)"
        );
    }
}