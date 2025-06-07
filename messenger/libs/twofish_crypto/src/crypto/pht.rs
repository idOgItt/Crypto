/// Pseudo-Hadamard Transform:
/// (a, b) → (a + b mod 2^32, a + 2·b mod 2^32)
pub fn pht(a: u32, b: u32) -> (u32, u32) {
    let sum = a.wrapping_add(b);
    let doubled = b.wrapping_mul(2);
    let total = a.wrapping_add(doubled);

    (sum, total)
}
