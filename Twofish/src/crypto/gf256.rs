/// Умножение в GF(2^8) по полиному x^8 + x^6 + x^5 + x^3 + 1
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a_val = a;
    let mut b_val = b;

    // Полином для Twofish: x^8 + x^6 + x^5 + x^3 + 1 = 0x169
    const POLYNOMIAL: u8 = 0x69; // без старшего бита, который подразумевается

    // Школьный алгоритм умножения
    for _ in 0..8 {
        // Если младший бит b установлен, добавляем текущее значение a к результату
        if b_val & 1 != 0 {
            result ^= a_val;
        }

        // Запоминаем старший бит a
        let high_bit = a_val & 0x80;

        // Сдвигаем a влево на 1 бит
        a_val <<= 1;

        // Если старший бит был установлен, выполняем редукцию по модулю полинома
        if high_bit != 0 {
            a_val ^= POLYNOMIAL;
        }

        // Сдвигаем b вправо на 1 бит
        b_val >>= 1;
    }

    result
}

/// Возведение в степень в том же поле
pub fn gf_pow(a: u8, exp: usize) -> u8 {
    if exp == 0 {
        return 1; // Любое число в степени 0 равно 1
    }

    if a == 0 {
        return 0; // 0 в любой положительной степени равно 0
    }

    let mut result: u8 = 1;
    let mut base = a;
    let mut exponent = exp;

    // Алгоритм быстрого возведения в степень (square-and-multiply)
    while exponent > 0 {
        if exponent & 1 != 0 {
            // Если текущий бит экспоненты установлен, умножаем результат на текущую степень базы
            result = gf_mul(result, base);
        }

        // Возводим базу в квадрат
        base = gf_mul(base, base);

        // Переходим к следующему биту экспоненты
        exponent >>= 1;
    }

    result
}