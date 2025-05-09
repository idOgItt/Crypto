use symmetric_cipher::crypto::key_expansion::KeyExpansion;
use crate::gf::arithmetic::{poly_mulmod, Poly};
use crate::rijndael::sbox::sbox;

/// Генерация всех раундовых ключей AES (KeyExpansion)
pub fn expand_key(key: &[u8], poly: &Poly) -> Vec<Vec<u8>> {
    // Nb=4, Nk = key.len()/4, Nr = Nk+6
    let nk = key.len() / 4;
    let nr = nk + 6;
    let nb = 4;
    let total_words = nb * (nr + 1);

    // Вспомогательные лямбды
    fn byte_to_poly(x: u8) -> Poly {
        let mut v = (0..8).map(|i| (x >> i) & 1 != 0).collect::<Vec<bool>>();
        v.push(false); // x⁸ = 0
        v
    }
    fn poly_to_byte(p: &Poly) -> u8 {
        p.iter()
            .take(8)
            .enumerate()
            .fold(0u8, |acc, (i, &b)| if b { acc | (1 << i) } else { acc })
    }
    fn gf_mul(a: u8, b: u8, poly: &Poly) -> u8 {
        let pa = byte_to_poly(a);
        let pb = byte_to_poly(b);
        poly_to_byte(&poly_mulmod(&pa, &pb, poly))
    }
    fn rot_word(w: [u8;4]) -> [u8;4] {
        [w[1], w[2], w[3], w[0]]
    }
    fn sub_word(w: [u8;4], poly: &Poly) -> [u8;4] {
        [ sbox(w[0], poly), sbox(w[1], poly), sbox(w[2], poly), sbox(w[3], poly) ]
    }
    // Rcon[i] = {02}⁽ⁱ⁻¹⁾ в GF(2⁸)
    let mut rcon = vec![0u8; nr+1];
    rcon[1] = 1;
    for i in 2..=nr {
        rcon[i] = gf_mul(rcon[i-1], 2, poly);
    }

    // W — вектор слов (4 байта каждое)
    let mut w = Vec::<[u8;4]>::with_capacity(total_words);
    // первые Nk слов — из ключа
    for i in 0..nk {
        let offset = 4*i;
        w.push([ key[offset], key[offset+1], key[offset+2], key[offset+3] ]);
    }
    // генерим остальные
    for i in nk..total_words {
        let mut temp = w[i-1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp), poly);
            temp[0] ^= rcon[i / nk];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp, poly);
        }
        let prev = w[i - nk];
        w.push([ prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3] ]);
    }

    // Собираем Vec<Vec<u8>>: по Nb слов на раунд
    let mut round_keys = Vec::with_capacity(nr+1);
    for round in 0..(nr+1) {
        let mut rk = Vec::with_capacity(4*nb);
        for word in &w[round*nb .. (round+1)*nb] {
            rk.extend_from_slice(word);
        }
        round_keys.push(rk);
    }
    round_keys
}

/// Обёртка-генератор ключей для AES, реализующая trait из symmetric_cipher
pub struct AesKeyExpansion {
    poly: Poly,
}

impl AesKeyExpansion {
    pub fn new(poly: Poly) -> Self {
        Self { poly }
    }
}

impl KeyExpansion for AesKeyExpansion {
    fn generate_round_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        expand_key(key, &self.poly)
    }
}
