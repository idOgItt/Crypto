#[cfg(test)]
mod tests {
    use twofish::crypto::gf256::{gf_mul, gf_pow};
    use super::*;

    #[test]
    fn test_gf_mul_basic() {
        // Базовые случаи умножения
        assert_eq!(gf_mul(0, 0), 0);       // 0 * 0 = 0
        assert_eq!(gf_mul(1, 0), 0);       // 1 * 0 = 0
        assert_eq!(gf_mul(0, 1), 0);       // 0 * 1 = 0
        assert_eq!(gf_mul(1, 1), 1);       // 1 * 1 = 1
    }

    #[test]
    fn test_gf_mul_commutative() {
        // Проверка коммутативности: a * b = b * a
        let test_values = [1, 2, 3, 0x10, 0x20, 0xAA, 0xFF];

        for &a in &test_values {
            for &b in &test_values {
                assert_eq!(
                    gf_mul(a, b), gf_mul(b, a),
                    "GF умножение должно быть коммутативным: {} * {} = {} * {}",
                    a, b, b, a
                );
            }
        }
    }

    #[test]
    fn test_gf_mul_distributive() {
        // Проверка дистрибутивности: a * (b ⊕ c) = (a * b) ⊕ (a * c)
        let test_values = [1, 2, 3, 0x10, 0x20, 0xAA, 0xFF];

        for &a in &test_values {
            for &b in &test_values {
                for &c in &test_values {
                    let left = gf_mul(a, b ^ c);
                    let right = gf_mul(a, b) ^ gf_mul(a, c);

                    assert_eq!(
                        left, right,
                        "GF умножение должно быть дистрибутивным: {} * ({} ⊕ {}) = ({} * {}) ⊕ ({} * {})",
                        a, b, c, a, b, a, c
                    );
                }
            }
        }
    }

    #[test]
    fn test_gf_mul_associative() {
        // Проверка ассоциативности: (a * b) * c = a * (b * c)
        let test_values = [1, 2, 3, 0x10, 0x20];

        for &a in &test_values {
            for &b in &test_values {
                for &c in &test_values {
                    let left = gf_mul(gf_mul(a, b), c);
                    let right = gf_mul(a, gf_mul(b, c));

                    assert_eq!(
                        left, right,
                        "GF умножение должно быть ассоциативным: ({} * {}) * {} = {} * ({} * {})",
                        a, b, c, a, b, c
                    );
                }
            }
        }
    }

    #[test]
    fn test_gf_mul_known_values() {
        // Проверка известных значений для GF(2^8) с полиномом x^8 + x^6 + x^5 + x^3 + 1
        let test_cases = [
            (0x01, 0x01, 0x01),  // 1 * 1 = 1
            (0x02, 0x02, 0x04),  // 2 * 2 = 4
            (0x57, 0x83, 0xC1),  // 87 * 131 = 193
            (0x57, 0x13, 0xFE),  // 87 * 19 = 254
            (0x01, 0xFF, 0xFF),  // 1 * 255 = 255
            (0xFF, 0x02, 0xE5),  // 255 * 2 = 229
            (0xFF, 0xFF, 0xD6)   // 255 * 255 = 214
        ];

        for (a, b, expected) in test_cases {
            assert_eq!(
                gf_mul(a, b), expected,
                "GF умножение: {} * {} должно быть {}, получено {}",
                a, b, expected, gf_mul(a, b)
            );
        }
    }

    #[test]
    fn test_gf_pow_basic() {
        // Базовые случаи возведения в степень
        assert_eq!(gf_pow(0, 0), 1);       // 0^0 = 1 (по определению)
        assert_eq!(gf_pow(0, 1), 0);       // 0^1 = 0
        assert_eq!(gf_pow(1, 0), 1);       // 1^0 = 1
        assert_eq!(gf_pow(1, 100), 1);     // 1^n = 1
    }

    #[test]
    fn test_gf_pow_known_values() {
        // Проверка известных значений
        let test_cases = [
            (0x02, 1, 0x02),  // 2^1 = 2
            (0x02, 2, 0x04),  // 2^2 = 4
            (0x02, 3, 0x08),  // 2^3 = 8
            (0x02, 4, 0x10),  // 2^4 = 16
            (0x02, 8, 0x1D),  // 2^8 = 29 (из-за редукции по модулю)
            (0x03, 2, 0x09),  // 3^2 = 9
            (0x05, 3, 0xC9),  // 5^3 = 201
            (0xFF, 2, 0xD6),  // 255^2 = 214
            (0xFF, 3, 0x4E)   // 255^3 = 78
        ];

        for (a, exp, expected) in test_cases {
            assert_eq!(
                gf_pow(a, exp), expected,
                "GF возведение в степень: {}^{} должно быть {}, получено {}",
                a, exp, expected, gf_pow(a, exp)
            );
        }
    }

    #[test]
    fn test_gf_pow_via_mul() {
        // Проверка соотношения между gf_pow и gf_mul
        let test_values = [0x01, 0x02, 0x03, 0x10, 0xAA, 0xFF];

        for &a in &test_values {
            // a^2 = a * a
            assert_eq!(
                gf_pow(a, 2), gf_mul(a, a),
                "GF возведение в степень: {}^2 должно быть {} * {}, получено {}",
                a, a, a, gf_pow(a, 2)
            );

            // a^3 = a * a * a
            assert_eq!(
                gf_pow(a, 3), gf_mul(gf_mul(a, a), a),
                "GF возведение в степень: {}^3 должно быть {} * {} * {}, получено {}",
                a, a, a, a, gf_pow(a, 3)
            );
        }
    }

    #[test]
    fn test_gf_pow_properties() {
        // Проверка свойств возведения в степень
        let test_values = [0x01, 0x02, 0x03, 0x10, 0xAA];

        for &a in &test_values {
            // a^(m+n) = a^m * a^n
            let m = 2;
            let n = 3;
            assert_eq!(
                gf_pow(a, m + n), gf_mul(gf_pow(a, m), gf_pow(a, n)),
                "GF возведение в степень: {}^({} + {}) должно быть {}^{} * {}^{}, получено {}",
                a, m, n, a, m, a, n, gf_pow(a, m + n)
            );

            // (a^m)^n = a^(m*n)
            assert_eq!(
                gf_pow(gf_pow(a, m), n), gf_pow(a, m * n),
                "GF возведение в степень: ({}^{})^{} должно быть {}^({} * {}), получено {}",
                a, m, n, a, m, n, gf_pow(gf_pow(a, m), n)
            );
        }
    }
}