use crate::crypto::utils::{rotate_left, rotate_right};
use crate::crypto::sboxes::{q0, q1};
use crate::crypto::mds::mds_multiply;
use crate::crypto::key_schedule::expand_key;
use crate::crypto::pht::pht;
use symmetric_cipher::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds};

pub struct Twofish {
    key: Vec<u8>,
    round_keys: Vec<u32>,
    rounds: usize,
}

impl Twofish {
    pub fn new(key: &[u8]) -> Twofish {
        let key_len = key.len();
        if key_len != 16 && key_len != 24 && key_len != 32 {
            panic!("Invalid key length for Twofish: {}", key_len);
        }
        let round_keys = expand_key(key);
        Twofish {
            key: key.to_vec(),
            round_keys,
            rounds: 16,
        }
    }

    fn g(&self, x: u32) -> u32 {
        let key_bytes = &self.key;
        let key_len = key_bytes.len();

        let b0 = (x & 0xFF) as u8;
        let b1 = ((x >> 8) & 0xFF) as u8;
        let b2 = ((x >> 16) & 0xFF) as u8;
        let b3 = (x >> 24) as u8;

        let mut y0 = b0;
        let mut y1 = b1;
        let mut y2 = b2;
        let mut y3 = b3;

        if key_len == 32 {
            y0 = q1(y0) ^ key_bytes[24];
            y1 = q0(y1) ^ key_bytes[25];
            y2 = q0(y2) ^ key_bytes[26];
            y3 = q1(y3) ^ key_bytes[27];
        }

        if key_len >= 24 {
            y0 = q1(y0) ^ key_bytes[16];
            y1 = q1(y1) ^ key_bytes[17];
            y2 = q0(y2) ^ key_bytes[18];
            y3 = q0(y3) ^ key_bytes[19];
        }

        y0 = q1(q0(y0) ^ key_bytes[8]) ^ key_bytes[0];
        y1 = q0(q0(y1) ^ key_bytes[9]) ^ key_bytes[1];
        y2 = q1(q1(y2) ^ key_bytes[10]) ^ key_bytes[2];
        y3 = q0(q1(y3) ^ key_bytes[11]) ^ key_bytes[3];

        let word = ((y0 as u32) << 24)
            | ((y1 as u32) << 16)
            | ((y2 as u32) << 8)
            | (y3 as u32);
        mds_multiply(word)
    }

    fn f_function(&self, r0: u32, r1: u32, round: usize) -> (u32, u32) {
        let t0 = self.g(r0);
        let t1 = self.g(rotate_left(r1, 8));

        let (mut f0, mut f1) = pht(t0, t1);

        let rk_index = 2 * round + 8;
        f0 = f0.wrapping_add(self.round_keys[rk_index]);
        f1 = f1.wrapping_add(self.round_keys[rk_index + 1]);

        (f0, f1)
    }

    pub fn encrypt_block(&self, plaintext_block: &[u8]) -> Vec<u8> {
        if plaintext_block.len() != 16 {
            return Vec::new();
        }

        let mut block = [0u32; 4];
        for i in 0..4 {
            block[i] = (plaintext_block[4*i] as u32)
                | ((plaintext_block[4*i + 1] as u32) << 8)
                | ((plaintext_block[4*i + 2] as u32) << 16)
                | ((plaintext_block[4*i + 3] as u32) << 24);
        }

        for i in 0..4 {
            block[i] ^= self.round_keys[i];
        }

        for r in 0..self.rounds {
            let (f0, f1) = self.f_function(block[0], block[1], r);

            let new_r2 = rotate_right(block[2] ^ f0, 1);
            let new_r3 = rotate_left(block[3], 1) ^ f1;

            // Меняем половины местами
            let temp0 = block[0];
            let temp1 = block[1];
            block[0] = new_r2;
            block[1] = new_r3;
            block[2] = temp0;
            block[3] = temp1;
        }

        let temp0 = block[0];
        let temp1 = block[1];
        block[0] = block[2];
        block[1] = block[3];
        block[2] = temp0;
        block[3] = temp1;

        for i in 0..4 {
            block[i] ^= self.round_keys[i + 4];
        }

        let mut ciphertext = Vec::with_capacity(16);
        for i in 0..4 {
            ciphertext.push(block[i] as u8);
            ciphertext.push((block[i] >> 8) as u8);
            ciphertext.push((block[i] >> 16) as u8);
            ciphertext.push((block[i] >> 24) as u8);
        }
        ciphertext
    }

    pub fn decrypt_block(&self, ciphertext_block: &[u8]) -> Vec<u8> {
        if ciphertext_block.len() != 16 {
            return Vec::new();
        }

        let mut block = [0u32; 4];
        for i in 0..4 {
            block[i] = (ciphertext_block[4*i] as u32)
                | ((ciphertext_block[4*i + 1] as u32) << 8)
                | ((ciphertext_block[4*i + 2] as u32) << 16)
                | ((ciphertext_block[4*i + 3] as u32) << 24);
        }

        for i in 0..4 {
            block[i] ^= self.round_keys[i + 4];
        }

        let temp0 = block[0];
        let temp1 = block[1];
        block[0] = block[2];
        block[1] = block[3];
        block[2] = temp0;
        block[3] = temp1;

        for r in (0..self.rounds).rev() {
            let temp0 = block[0];
            let temp1 = block[1];
            block[0] = block[2];
            block[1] = block[3];
            block[2] = temp0;
            block[3] = temp1;

            let (f0, f1) = self.f_function(block[0], block[1], r);

            block[2] = rotate_left(block[2], 1) ^ f0;
            let temp = block[3] ^ f1;
            block[3] = rotate_right(temp, 1);
        }

        for i in 0..4 {
            block[i] ^= self.round_keys[i];
        }

        let mut plaintext = Vec::with_capacity(16);
        for i in 0..4 {
            plaintext.push(block[i] as u8);
            plaintext.push((block[i] >> 8) as u8);
            plaintext.push((block[i] >> 16) as u8);
            plaintext.push((block[i] >> 24) as u8);
        }
        plaintext
    }

    pub fn encrypt_with_rounds(&self, plaintext_block: &[u8], rounds: usize) -> Vec<u8> {
        let mut tmp = Twofish {
            key: self.key.clone(),
            round_keys: self.round_keys.clone(),
            rounds,
        };
        tmp.encrypt_block(plaintext_block)
    }

    pub fn decrypt_with_rounds(&self, ciphertext_block: &[u8], rounds: usize) -> Vec<u8> {
        let mut tmp = Twofish {
            key: self.key.clone(),
            round_keys: self.round_keys.clone(),
            rounds,
        };
        tmp.decrypt_block(ciphertext_block)
    }
}

impl CipherAlgorithm for Twofish {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len() % 16, 0, "Data length must be multiple of 16");

        data.chunks_exact(16)
            .flat_map(|chunk| self.encrypt_block(chunk))
            .collect()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len() % 16, 0, "Data length must be multiple of 16");

        data.chunks_exact(16)
            .flat_map(|chunk| self.decrypt_block(chunk))
            .collect()
    }
}

impl SymmetricCipher for Twofish {
    fn set_key(&mut self, key: &[u8]) -> Result<(), &'static str> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err("Invalid key length for Twofish");
        }
        self.key = key.to_vec();
        self.round_keys = expand_key(key);
        Ok(())
    }
}

impl SymmetricCipherWithRounds for Twofish {
    fn set_key_with_rounds(&mut self, _key: &[u8]) {
        todo!()
    }

    fn encrypt_block(&self, data: &[u8], _round_key: &[u8]) -> Vec<u8> {
        self.encrypt_block(data)
    }

    fn decrypt_block(&self, data: &[u8], _round_key: &[u8]) -> Vec<u8> {
        self.decrypt_block(data)
    }

    fn block_size(&self) -> usize {
        16
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        Some(self.round_keys.iter()
            .flat_map(|&k| k.to_le_bytes())
            .collect())
    }
}