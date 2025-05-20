#[cfg(test)]
mod tests {
    use twofish::crypto::pht::pht;
    use super::*;

    #[test]
    fn test_pht_basic() {
        // Базовый тест с простыми числами
        let (a, b) = pht(1, 2);
        assert_eq!(a, 3);    // 1 + 2 = 3
        assert_eq!(b, 5);    // 1 + 2*2 = 5

        // Еще один простой тест
        let (a, b) = pht(10, 20);
        assert_eq!(a, 30);   // 10 + 20 = 30
        assert_eq!(b, 50);   // 10 + 2*20 = 50
    }

    #[test]
    fn test_pht_zero() {
        // Проверка с нулевыми входными данными
        let (a, b) = pht(0, 0);
        assert_eq!(a, 0);
        assert_eq!(b, 0);

        // Проверка с одним нулевым входом
        let (a, b) = pht(0, 5);
        assert_eq!(a, 5);    // 0 + 5 = 5
        assert_eq!(b, 10);   // 0 + 2*5 = 10

        let (a, b) = pht(5, 0);
        assert_eq!(a, 5);    // 5 + 0 = 5
        assert_eq!(b, 5);    // 5 + 2*0 = 5
    }

    #[test]
    fn test_pht_large_values() {
        // Проверка с большими значениями
        let a = 0x7FFFFFFF;  // Почти максимальное положительное 32-битное значение
        let b = 0x7FFFFFFF;

        let (result_a, result_b) = pht(a, b);

        // a + b должно переполниться и стать отрицательным
        assert_eq!(result_a, 0xFFFFFFFE); // -2 в дополнительном коде

        // a + 2*b должно переполниться дважды
        assert_eq!(result_b, 0x7FFFFFFD); // 2^31 - 3
    }

    #[test]
    fn test_pht_wrapping() {
        // Проверка переполнения при сложении и умножении
        let (a, b) = pht(0xFFFFFFFF, 0xFFFFFFFF);

        // 0xFFFFFFFF + 0xFFFFFFFF = 0x1FFFFFFFE, но в u32 это 0xFFFFFFFE
        assert_eq!(a, 0xFFFFFFFE);

        // 0xFFFFFFFF + 2*0xFFFFFFFF = 0xFFFFFFFF + 0xFFFFFFFE = 0x1FFFFFFFD, 
        // но в u32 это 0xFFFFFFFD
        assert_eq!(b, 0xFFFFFFFD);
    }

    #[test]
    fn test_pht_multiple_examples() {
        // Несколько дополнительных примеров
        let test_cases = [
            // (input_a,    input_b,    expected_a, expected_b)
            (0x01234567, 0x89ABCDEF, 0x8ACF1356, 0x147AE145),
            (0x00000000, 0x00000001, 0x00000001, 0x00000002),
            (0xAAAAAAAA, 0x55555555, 0xFFFFFFFF, 0x55555554),
            (0x12345678, 0x12345678, 0x2468ACF0, 0x369D0368),
        ];

        for (input_a, input_b, expected_a, expected_b) in test_cases {
            let (result_a, result_b) = pht(input_a, input_b);
            assert_eq!(
                result_a, expected_a,
                "PHT({:08X}, {:08X}) первый результат должен быть {:08X}, получено {:08X}",
                input_a, input_b, expected_a, result_a
            );
            assert_eq!(
                result_b, expected_b,
                "PHT({:08X}, {:08X}) второй результат должен быть {:08X}, получено {:08X}",
                input_a, input_b, expected_b, result_b
            );
        }
    }
}