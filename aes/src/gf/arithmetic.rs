/// Полином над GF(2), представленный как вектор битов.
/// poly[i] — коэффициент при x^i
pub type Poly = Vec<bool>;

/// Сложение полиномов в GF(2): XOR поразрядно
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    todo!("XOR полиномов")
}

/// Умножение полиномов в GF(2)
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    todo!("Умножение по модулю 2")
}

/// Деление с остатком: (частное, остаток)
pub fn poly_divmod(dividend: &Poly, divisor: &Poly) -> (Poly, Poly) {
    todo!("Деление полиномов в GF(2)")
}

/// Остаток от деления: a % modulus
pub fn poly_mod(a: &Poly, modulus: &Poly) -> Poly {
    let (_, rem) = poly_divmod(a, modulus);
    rem
}

/// Умножение с модулем: (a * b) mod modulus
pub fn poly_mulmod(a: &Poly, b: &Poly, modulus: &Poly) -> Poly {
    let product = poly_mul(a, b);
    poly_mod(&product, modulus)
}

/// Возведение в степень: a^exp mod modulus
pub fn poly_powmod(base: &Poly, exp: usize, modulus: &Poly) -> Poly {
    todo!("Быстрое возведение в степень")
}

/// Обратный элемент по модулю: a⁻¹ mod modulus
pub fn poly_inv(a: &Poly, modulus: &Poly) -> Poly {
    todo!("Расширенный алгоритм Евклида для полиномов")
}
