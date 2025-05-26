use crate::crypto::cipher_types::PaddingMode;
use bitvec::prelude::BitVec;
use rand::TryRngCore;
use rand::rngs::OsRng;

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

pub fn apply_padding(mut data: Vec<u8>, block_size: usize, padding: PaddingMode) -> Vec<u8> {
    let padding_length = if data.len() % block_size == 0 && !data.is_empty() {
        if matches!(
            padding,
            PaddingMode::PKCS7 | PaddingMode::ANSI_X923 | PaddingMode::ISO10126
        ) {
            if data.len() % block_size == 0 {
                return data;
            }
            block_size
        } else {
            0
        }
    } else {
        block_size - (data.len() % block_size)
    };

    if padding_length == 0 {
        return data;
    }

    match padding {
        PaddingMode::Zeros => data.extend(vec![0; padding_length]),
        PaddingMode::ANSI_X923 => {
            data.extend(vec![0; padding_length - 1]);
            data.push(padding_length as u8);
        }
        PaddingMode::PKCS7 => {
            data.extend(vec![padding_length as u8; padding_length]);
        }
        PaddingMode::ISO10126 => {
            let mut rng = OsRng;
            let mut padding = vec![0u8; padding_length - 1];
            rng.try_fill_bytes(&mut padding)
                .expect("Failed to fill ISO10126 padding");
            data.extend(padding.into_iter());
            data.push(padding_length as u8);
        }
    }
    data
}

pub fn is_full_padding_block(data: &[u8], block_size: usize, padding: &PaddingMode) -> bool {
    if data.len() != block_size {
        return false;
    }

    match padding {
        PaddingMode::PKCS7 => {
            let pad_len = data[block_size - 1] as usize;
            pad_len == block_size && data.iter().all(|&b| b == pad_len as u8)
        }
        PaddingMode::ANSI_X923 => {
            let pad_len = data[block_size - 1] as usize;
            pad_len == block_size && data[..block_size - 1].iter().all(|&b| b == 0)
        }
        PaddingMode::ISO10126 => {
            let pad_len = data[block_size - 1] as usize;
            pad_len == block_size // остальное может быть любым
        }
        _ => false
    }
}


pub fn remove_padding(mut data: Vec<u8>, padding: PaddingMode) -> Vec<u8> {
    //eprintln!("remove_padding called on: {:?}", data);
    let block_size = data.len();
    let is_full_padding_block = is_full_padding_block(&data, block_size, &padding);

    if is_full_padding_block {
        return Vec::new();
    }

    match padding {
        PaddingMode::Zeros => {
            while data.last() == Some(&0u8) {
                data.pop();
            }
        }
        PaddingMode::PKCS7 => {
            if let Some(&last_byte) = data.last() {
                let pad_len = last_byte as usize;
                if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
                    //eprintln!("PKCS7: Invalid padding length: {}", pad_len);
                    return data;
                }
                if data[data.len() - pad_len..].iter().all(|&b| b == last_byte) {
                    data.truncate(data.len() - pad_len);
                }
            }
        }
        PaddingMode::ANSI_X923 => {
            if let Some(&last_byte) = data.last() {
                let pad_len = last_byte as usize;
                if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
                    //eprintln!("ANSI_X923: Invalid padding length: {}", pad_len);
                    return data;
                }
                let pad_region = &data[data.len() - pad_len..data.len() - 1];
                if pad_region.iter().all(|&b| b == 0) {
                    data.truncate(data.len() - pad_len);
                }
            }
        }
        PaddingMode::ISO10126 => {
            if let Some(&last_byte) = data.last() {
                let pad_len = last_byte as usize;
                if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
                    //eprintln!("ISO10126: Invalid padding length: {}", pad_len);
                    return data;
                }
                data.truncate(data.len() - pad_len);
            }
        }
    }

    data
}



pub fn normalize_block(
    mut block: Vec<u8>,
    block_size: usize,
    encrypt: bool,
    padding: PaddingMode,
) -> Vec<u8> {
    if block.len() < block_size {
        if encrypt {
            apply_padding(block, block_size, padding)
        } else {
            block.resize(block_size, 0);
            block
        }
    } else {
        block
    }
}
