use bitvec::prelude::BitVec;

pub fn shift_bits_little_endian(
    data: &[u8],
    p_block: &[usize],
    little_endian: bool,
    start_index: usize,
) -> Vec<u8> {
    let mut data = data.to_vec();

    if little_endian {
        data.reverse();
    }

    let bits = bytes_to_bits(&data);
    let bit_count = bits.len();
    let mut permuted_bits = BitVec::with_capacity(bit_count);

    for &pos in p_block {
        let adjusted_pos = pos.saturating_sub(start_index);
        if adjusted_pos < bit_count {
            permuted_bits.push(bits[adjusted_pos]);
        } else {
            permuted_bits.push(false);
        }
    }

    let mut result = bits_to_bytes(&permuted_bits);

    result.reverse();
    result
}

pub fn bytes_to_bits(input: &[u8]) -> BitVec {
    let mut bits = BitVec::with_capacity(input.len() * 8);
    for &byte in input {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 != 0);
        }
    }
    bits
}

pub fn bits_to_bytes(bits: &BitVec) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(bits.len() / 8);

    for chunk in bits.chunks(8) {
        let mut byte = 0;
        for (i, bit) in chunk.iter().enumerate() {
            if *bit {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }
    bytes
}
