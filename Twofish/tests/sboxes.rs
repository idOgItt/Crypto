#[cfg(test)]
mod tests {
    use twofish::crypto::sboxes::{q0, q1, Q0, Q1};
    use super::*;

    #[test]
    fn test_q0_values() {
        // Проверка некоторых известных значений из таблицы Q0
        assert_eq!(q0(0), 0xa9);
        assert_eq!(q0(1), 0x67);
        assert_eq!(q0(255), 0xe0);
        assert_eq!(q0(128), 0xa1);

        // Проверка случайных значений по индексу
        assert_eq!(q0(42), 0xf7);
        assert_eq!(q0(100), 0x53);
        assert_eq!(q0(200), 0x57);
    }

    #[test]
    fn test_q1_values() {
        // Проверка некоторых известных значений из таблицы Q1
        assert_eq!(q1(0), 0x75);
        assert_eq!(q1(1), 0xf3);
        assert_eq!(q1(255), 0x91);
        assert_eq!(q1(128), 0x66);

        // Проверка случайных значений по индексу
        assert_eq!(q1(42), 0x42);
        assert_eq!(q1(100), 0x69);
        assert_eq!(q1(200), 0x09);
    }

    #[test]
    fn test_q0_complete() {
        // Проверка, что таблица Q0 имеет ожидаемый размер
        assert_eq!(Q0.len(), 256);

        // Проверка, что все значения в таблице Q0 соответствуют вызовам функции q0
        for i in 0..256 {
            assert_eq!(Q0[i], q0(i as u8));
        }
    }

    #[test]
    fn test_q1_complete() {
        // Проверка, что таблица Q1 имеет ожидаемый размер
        assert_eq!(Q1.len(), 256);

        // Проверка, что все значения в таблице Q1 соответствуют вызовам функции q1
        for i in 0..256 {
            assert_eq!(Q1[i], q1(i as u8));
        }
    }

    #[test]
    fn test_q_boxes_uniqueness() {
        // Проверка, что в таблицах нет дубликатов (необязательно для Q-боксов,
        // но полезно убедиться, что таблицы имеют хорошие свойства)
        let mut q0_values = std::collections::HashSet::new();
        let mut q1_values = std::collections::HashSet::new();

        for i in 0..256 {
            q0_values.insert(Q0[i]);
            q1_values.insert(Q1[i]);
        }

        // Если все значения уникальны, размер HashSet должен быть 256
        assert_eq!(q0_values.len(), 256);
        assert_eq!(q1_values.len(), 256);
    }
}