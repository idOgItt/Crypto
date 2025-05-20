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
    fn test_mds_specific_vectors() {
        // Из документации Twofish или известных тестовых векторов
        let test_cases = [
            (0x00000000, 0x00000000),
            (0x01010101, 0xBDBDBDBD),
            (0xFFFFFFFF, 0x7C957C96)
        ];

        for (input, expected) in test_cases {
            let result = mds_multiply(input);
            assert_eq!(
                result, expected,
                "MDS умножение для 0x{:08X}: ожидалось 0x{:08X}, получено 0x{:08X}",
                input, expected, result
            );
        }
    }

    #[test]
    fn test_mds_single_byte() {
        // Тестирование обработки отдельных байтов

        // Только старший байт
        let input = 0x01000000;
        let result = mds_multiply(input);
        let expected = 0x01EF5BEF;
        assert_eq!(result, expected);

        // Только второй байт
        let input = 0x00010000;
        let result = mds_multiply(input);
        let expected = 0xEFEF5B01;
        assert_eq!(result, expected);

        // Только третий байт
        let input = 0x00000100;
        let result = mds_multiply(input);
        let expected = 0x5BEF01EF;
        assert_eq!(result, expected);

        // Только младший байт
        let input = 0x00000001;
        let result = mds_multiply(input);
        let expected = 0x5B01EF5B;
        assert_eq!(result, expected);
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