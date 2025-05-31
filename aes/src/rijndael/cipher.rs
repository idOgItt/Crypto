use crate::gf::arithmetic::{poly_mulmod, Poly};
use crate::rijndael::key_schedule::expand_key;
use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm,
    SymmetricCipher,
    SymmetricCipherWithRounds,
};
use crate::rijndael::sbox::{inv_sbox, sbox};

type State = Vec<[u8; 4]>;

fn block_to_state(block: &[u8], nb: usize) -> State {
    let mut s = vec![[0u8; 4]; nb];
    for c in 0..nb {
        for r in 0..4 {
            s[c][r] = block[c * 4 + r];
        }
    }
    s
}

fn state_to_block(s: &State) -> Vec<u8> {
    let nb = s.len();
    let mut out = vec![0u8; 4 * nb];
    for c in 0..nb {
        for r in 0..4 {
            out[c * 4 + r] = s[c][r];
        }
    }
    out
}

fn gf_mul_byte(a: u8, b: u8, poly: &Poly) -> u8 {
    let pa = byte_to_poly(a);
    let pb = byte_to_poly(b);
    let prod = poly_mulmod(&pa, &pb, poly);
    poly_to_byte(&prod)
}

fn byte_to_poly(x: u8) -> Poly {
    let mut v = Vec::with_capacity(9);
    for i in 0..8 {
        v.push((x >> i) & 1 != 0);
    }
    v.push(false);
    v
}

fn poly_to_byte(p: &Poly) -> u8 {
    p.iter()
        .take(8)
        .enumerate()
        .fold(0u8, |acc, (i, &b)| if b { acc | (1 << i) } else { acc })
}

fn add_round_key(state: &mut State, round_key: &[u8]) {
    let nb = state.len();
    for c in 0..nb {
        for r in 0..4 {
            let idx = c * 4 + r;
            if idx < round_key.len() {
                state[c][r] ^= round_key[idx];
            } else {
                println!("Error: round_key index {} out of bounds (len: {})", idx, round_key.len());
            }
        }
    }
}

fn sub_bytes(state: &mut State, poly: &Poly) {
    for col in state.iter_mut() {
        for byte in col.iter_mut() {
            *byte = sbox(*byte, poly);
        }
    }
}

fn inv_sub_bytes(state: &mut State, poly: &Poly) {
    for col in state.iter_mut() {
        for byte in col.iter_mut() {
            *byte = inv_sbox(*byte, poly);
        }
    }
}

fn shift_rows(state: &mut State) {
    let nb = state.len();
    for r in 1..4 {
        let mut tmp = vec![0u8; nb];
        for c in 0..nb {
            tmp[c] = state[(c + r) % nb][r];
        }
        for c in 0..nb {
            state[c][r] = tmp[c];
        }
    }
}

fn inv_shift_rows(state: &mut State) {
    let nb = state.len();
    for r in 1..4 {
        let mut tmp = vec![0u8; nb];
        for c in 0..nb {
            tmp[c] = state[(c + nb - r) % nb][r];
        }
        for c in 0..nb {
            state[c][r] = tmp[c];
        }
    }
}

fn mix_columns(state: &mut State, poly: &Poly) {
    for col in state.iter_mut() {
        let a = *col;
        col[0] = gf_mul_byte(a[0], 2, poly)
            ^ gf_mul_byte(a[1], 3, poly)
            ^ a[2] ^ a[3];
        col[1] = a[0]
            ^ gf_mul_byte(a[1], 2, poly)
            ^ gf_mul_byte(a[2], 3, poly)
            ^ a[3];
        col[2] = a[0] ^ a[1]
            ^ gf_mul_byte(a[2], 2, poly)
            ^ gf_mul_byte(a[3], 3, poly);
        col[3] = gf_mul_byte(a[0], 3, poly)
            ^ a[1] ^ a[2]
            ^ gf_mul_byte(a[3], 2, poly);
    }
}

fn inv_mix_columns(state: &mut State, poly: &Poly) {
    for col in state.iter_mut() {
        let a = *col;
        col[0] = gf_mul_byte(a[0], 0x0e, poly)
            ^ gf_mul_byte(a[1], 0x0b, poly)
            ^ gf_mul_byte(a[2], 0x0d, poly)
            ^ gf_mul_byte(a[3], 0x09, poly);
        col[1] = gf_mul_byte(a[0], 0x09, poly)
            ^ gf_mul_byte(a[1], 0x0e, poly)
            ^ gf_mul_byte(a[2], 0x0b, poly)
            ^ gf_mul_byte(a[3], 0x0d, poly);
        col[2] = gf_mul_byte(a[0], 0x0d, poly)
            ^ gf_mul_byte(a[1], 0x09, poly)
            ^ gf_mul_byte(a[2], 0x0e, poly)
            ^ gf_mul_byte(a[3], 0x0b, poly);
        col[3] = gf_mul_byte(a[0], 0x0b, poly)
            ^ gf_mul_byte(a[1], 0x0d, poly)
            ^ gf_mul_byte(a[2], 0x09, poly)
            ^ gf_mul_byte(a[3], 0x0e, poly);
    }
}

fn encrypt_block_internal(
    block: &[u8],
    round_keys: &[Vec<u8>],
    poly: &Poly,
    nb: usize,
) -> Vec<u8> {
    let mut state = block_to_state(block, nb);

    add_round_key(&mut state, &round_keys[0]);
    let nr = round_keys.len() - 1;
    
    for round in 1..nr {
        sub_bytes(&mut state, poly);
        shift_rows(&mut state);
        mix_columns(&mut state, poly);
        add_round_key(&mut state, &round_keys[round]);
    }
    sub_bytes(&mut state, poly);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[nr]);
    state_to_block(&state)
}

fn decrypt_block_internal(
    block: &[u8],
    round_keys: &[Vec<u8>],
    poly: &Poly,
    nb: usize,
) -> Vec<u8> {
    let mut state = block_to_state(block, nb);
    let nr = round_keys.len() - 1;
    // initial
    add_round_key(&mut state, &round_keys[nr]);
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state, poly);
    // middle rounds
    for round in (1..nr).rev() {
        add_round_key(&mut state, &round_keys[round]);
        inv_mix_columns(&mut state, poly);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state, poly);
    }
    add_round_key(&mut state, &round_keys[0]);
    state_to_block(&state)
}

pub struct Rijndael {
    poly:       Poly,
    round_keys: Vec<Vec<u8>>,
    block_size: usize,
}

impl Rijndael {
    pub fn new(poly: Poly, block_size: usize) -> Self {
        Self {
            poly,
            round_keys: Vec::new(),
            block_size,
        }
    }
}

impl CipherAlgorithm for Rijndael {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let bs = self.block_size * 4;
        data.chunks(bs)
            .flat_map(|chunk| {
                encrypt_block_internal(chunk, &self.round_keys, &self.poly, self.block_size)
            })
            .collect()
    }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let bs = self.block_size * 4;
        data.chunks(bs)
            .flat_map(|chunk| {
                decrypt_block_internal(chunk, &self.round_keys, &self.poly, self.block_size)
            })
            .collect()
    }
}

impl SymmetricCipher for Rijndael {
    fn set_key(&mut self, key: &[u8]) -> Result<(), &'static str> {
        self.round_keys = expand_key(key, &self.poly, self.block_size * 4);
        Ok(())
    }
}

impl SymmetricCipherWithRounds for Rijndael {
    fn set_key_with_rounds(&mut self, key: &[u8]) {
        self.round_keys = expand_key(key, &self.poly, self.block_size * 4);
    }
    fn encrypt_block(&self, block: &[u8], _round_key: &[u8]) -> Vec<u8> {
        encrypt_block_internal(block, &self.round_keys, &self.poly, self.block_size)
    }
    fn decrypt_block(&self, block: &[u8], _round_key: &[u8]) -> Vec<u8> {
        decrypt_block_internal(block, &self.round_keys, &self.poly, self.block_size)
    }
    fn block_size(&self) -> usize {
        self.block_size * 4
    }
    fn export_round_keys(&self) -> Option<Vec<u8>> {
        Some(self.round_keys.iter().flatten().copied().collect())
    }
}
