use crate::crypto::des_tables::{E, P, S_BOXES};
use crate::crypto::encryption_transformation::EncryptionTransformation;
use crate::crypto::utils::shift_bits_little_endian;
pub struct DesTransformation;

fn get_bit(data: &[u8], bit_pos: usize) -> u8 {
    let byte = bit_pos / 8;
    let bit = bit_pos % 8; // LSB-first
    (data[byte] >> bit) & 1
}

fn set_next_4_bits(dest: &mut [u8; 4], val: u8, start_bit: usize) {
    for i in 0..4 {
        let bit_val = (val >> (3 - i)) & 1;
        let bit_pos = start_bit + i;
        let byte = bit_pos / 8;
        let bit = bit_pos % 8;
        dest[byte] |= bit_val << bit;
    }
}

fn xor_parts(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

impl EncryptionTransformation for DesTransformation {
    fn transform(&self, r_block: &[u8], round_key: &[u8]) -> Vec<u8> {

        // 1. Expansion
        let expanded = shift_bits_little_endian(r_block, &E, true, 1);

        // 2. XOR
        let mixed = xor_parts(&expanded, round_key);

        // 3. S-boxes
        let mut s_result = [0u8; 4];
        let mut bit_index = 0;

        for box_i in 0..8 {
            let start = box_i * 6;
            let row = (get_bit(&mixed, start) << 1) | get_bit(&mixed, start + 5);
            let mut col = 0;
            for j in 1..5 {
                col = (col << 1) | get_bit(&mixed, start + j);
            }
            let s_val = S_BOXES[box_i][(row * 16 + col) as usize];
            set_next_4_bits(&mut s_result, s_val as u8, bit_index);
            bit_index += 4;
        }


        // 4. P-permutation
        let permuted = shift_bits_little_endian(&s_result, &P, true, 1);

        permuted
    }
}
