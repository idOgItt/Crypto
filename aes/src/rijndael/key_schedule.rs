use symmetric_cipher::crypto::key_expansion::KeyExpansion;
use crate::gf::arithmetic::{poly_mulmod, Poly};
use crate::rijndael::sbox::sbox;

pub fn expand_key(key: &[u8], poly: &Poly, block_size: usize) -> Vec<Vec<u8>> {
    let nk = key.len() / 4;
    let nb = block_size / 4;
    let nr = std::cmp::max(nk, nb) + 6;
    let total_words = nb * (nr + 1);

    fn byte_to_poly(x: u8) -> Poly {
        let mut v = (0..8).map(|i| (x >> i) & 1 != 0).collect::<Vec<bool>>();
        v.push(false);
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

    let mut rcon = vec![0u8; nr+1];
    rcon[1] = 1;
    for i in 2..=nr {
        rcon[i] = gf_mul(rcon[i-1], 2, poly);
    }

    let mut w = Vec::<[u8;4]>::with_capacity(total_words);
    for i in 0..nk {
        let offset = 4*i;
        w.push([ key[offset], key[offset+1], key[offset+2], key[offset+3] ]);
    }

    for i in nk..total_words {
        let mut temp = w[i-1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp), poly);
            if i / nk < rcon.len() {
                temp[0] ^= rcon[i / nk];
            }
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp, poly);
        }
        let prev = w[i - nk];
        w.push([ prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3] ]);
    }

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

pub struct AesKeyExpansion {
    poly: Poly,
    block_size: usize,
}

impl AesKeyExpansion {
    pub fn new(poly: Poly, block_size: usize) -> Self {
        Self { poly, block_size }
    }

    pub fn poly(&self) -> &Poly {
        &self.poly
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }
}

impl KeyExpansion for AesKeyExpansion {
    fn generate_round_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        expand_key(key, &self.poly, self.block_size)
    }
}
