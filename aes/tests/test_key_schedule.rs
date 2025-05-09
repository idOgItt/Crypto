use rijndael::gf::arithmetic::Poly;
use rijndael::rijndael::key_schedule::expand_key;

/// Вспомогалка: строит Poly из среза битов (0 или 1)
fn poly_from_bits(bits: &[u8]) -> Poly {
    bits.iter().map(|&b| b != 0).collect()
}

/// Вспомогалка: превращает слайс в массив нужной длины
fn array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut arr = [0u8; N];
    arr.copy_from_slice(slice);
    arr
}

#[test]
fn test_aes128_schedule_length_and_first() {
    // AES-128: Nk=4, Nr=10 → Nr+1=11 раундовых ключей
    let key = array::<16>(&[
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c,
    ]);
    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]); // AES-полином 0x11B
    let schedule = expand_key(&key, &poly);

    assert_eq!(schedule.len(), 11, "AES-128 должно дать 11 раундовых ключей");
    // Первый раундовый ключ = исходный
    assert_eq!(schedule[0].as_slice(), &key);
}

#[test]
fn test_aes128_round1_matches_fips() {
    // Пример из FIPS-197, Appendix A.1
    let key = array::<16>(&[
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c,
    ]);
    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]);
    let schedule = expand_key(&key, &poly);

    let expected_round1 = array::<16>(&[
        0xa0,0xfa,0xfe,0x17, 0x88,0x54,0x2c,0xb1,
        0x23,0xa3,0x39,0x39, 0x2a,0x6c,0x76,0x05,
    ]);
    assert_eq!(
        schedule[1].as_slice(),
        &expected_round1,
        "Первый раунд AES-128 не совпал с FIPS-197"
    );
}

#[test]
fn test_aes192_schedule_length() {
    // AES-192: Nk=6, Nr=12 → Nr+1=13 раундовых ключей
    let key = [0u8; 24];
    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]);
    let schedule = expand_key(&key, &poly);
    assert_eq!(schedule.len(), 13, "AES-192 должно дать 13 раундовых ключей");
    // Каждый ключ — 16 байт
    for rk in &schedule {
        assert_eq!(rk.len(), 16);
    }
}

#[test]
fn test_aes256_schedule_length() {
    // AES-256: Nk=8, Nr=14 → Nr+1=15 раундовых ключей
    let key = [0u8; 32];
    let poly = poly_from_bits(&[1,1,0,1,1,0,0,0,1]);
    let schedule = expand_key(&key, &poly);
    assert_eq!(schedule.len(), 15, "AES-256 должно дать 15 раундовых ключей");
    for rk in &schedule {
        assert_eq!(rk.len(), 16);
    }
}
