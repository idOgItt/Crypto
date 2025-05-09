use rijndael::gf::arithmetic::Poly;
use rijndael::rijndael::sbox::{sbox, inv_sbox};

/// Вспомогалка: строит Poly из среза битов (0 или 1)
fn poly_from_bits(bits: &[u8]) -> Poly {
    bits.iter().map(|&b| b != 0).collect()
}

/// Стандартный неприводимый полином AES: x⁸ + x⁴ + x³ + x + 1
fn aes_poly() -> Poly {
    poly_from_bits(&[1, 1, 0, 1, 1, 0, 0, 0, 1])
}

#[test]
fn test_sbox_roundtrip_all() {
    let poly = aes_poly();
    for x in 0u8..=255 {
        let y = sbox(x, &poly);
        let x2 = inv_sbox(y, &poly);
        assert_eq!(x2, x, "round-trip failed for x = {:#04x}", x);
    }
}

#[test]
fn test_sbox_permutation() {
    let poly = aes_poly();
    let mut seen = [false; 256];
    for x in 0u8..=255 {
        let y = sbox(x, &poly) as usize;
        assert!(!seen[y], "duplicate output for x = {:#04x}", x);
        seen[y] = true;
    }
}

#[test]
fn test_sbox_zero_and_inv() {
    let poly = aes_poly();
    // Из спецификации AES: S(0x00) = 0x63
    assert_eq!(sbox(0x00, &poly), 0x63);
    // Обратное S-блоку: InvS(0x63) = 0x00
    assert_eq!(inv_sbox(0x63, &poly), 0x00);
}

#[test]
fn test_sbox_known_values() {
    let poly = aes_poly();
    // Спецификация (FIPS-197, Appendix A2):
    assert_eq!(sbox(0x01, &poly), 0x7c);
    assert_eq!(sbox(0x53, &poly), 0xed);
    assert_eq!(sbox(0x6d, &poly), 0xa4);
    // Проверяем обратные
    assert_eq!(inv_sbox(0x7c, &poly), 0x01);
    assert_eq!(inv_sbox(0xed, &poly), 0x53);
    assert_eq!(inv_sbox(0xa4, &poly), 0x6d);
}

#[test]
fn test_sbox_affine_properties() {
    let poly = aes_poly();
    // affine( inv( inv(x) ) ) == x for a few samples
    for &x in &[0x10u8, 0xab, 0xff, 0x5c] {
        let y = sbox(x, &poly);
        let z = sbox(inv_sbox(x, &poly), &poly);
        // оба обращения дают разные, но оба должны invert correctly
        assert_eq!(inv_sbox(y, &poly), x);
        assert_eq!(sbox(inv_sbox(x, &poly), &poly), x);
    }
}

#[test]
fn test_sbox_known_positions() {
    let poly = aes_poly();
    // Тестируем несколько фиксированных позиций из FIPS-197, Appendix A.2:
    // 0x10 → 0xCA, 0x20 → 0xB7, 0x30 → 0x04
    assert_eq!(sbox(0x10, &poly), 0xCA);
    assert_eq!(inv_sbox(0xCA, &poly), 0x10);
    assert_eq!(sbox(0x20, &poly), 0xB7);
    assert_eq!(inv_sbox(0xB7, &poly), 0x20);
    assert_eq!(sbox(0x30, &poly), 0x04);
    assert_eq!(inv_sbox(0x04, &poly), 0x30);
}

#[test]
fn test_sbox_no_fixed_points() {
    let poly = aes_poly();
    // Для всех x: S(x) != x
    for x in 0u8..=255 {
        let y = sbox(x, &poly);
        assert_ne!(y, x, "Найдён неподвижный элемент: x = {:#04x}", x);
    }
}

#[test]
fn test_sbox_non_linearity_sample() {
    let poly = aes_poly();
    // Проверим на одном выборочном примере, что S(x⊕y) != S(x)⊕S(y)
    let x = 0x57;
    let y = 0x83;
    let lhs = sbox(x ^ y, &poly);
    let rhs = sbox(x, &poly) ^ sbox(y, &poly);
    assert_ne!(
        lhs, rhs,
        "Нелинейность S-блока нарушена: S({:#04x}⊕{:#04x}) == S({:#04x})⊕S({:#04x})",
        x, y, x, y
    );
}

#[test]
fn test_sbox_random_roundtrip_samples() {
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;
    let poly = aes_poly();
    let mut rng = StdRng::seed_from_u64(0x1234_5678);
    // Несколько случайных проверок раунд-трипа
    for _ in 0..16 {
        let x = rng.next_u32() as u8;
        let y = sbox(x, &poly);
        let x2 = inv_sbox(y, &poly);
        assert_eq!(x2, x, "Round-trip failed for x = {:#04x}", x);
    }
}

