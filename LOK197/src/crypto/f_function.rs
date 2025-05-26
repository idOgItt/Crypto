// src/crypto/f_function.rs

use crate::crypto::sboxes::{s1, s2};
use crate::crypto::permutation::P;


pub fn round_function(input: u64, round_key: u64) -> u64 {
    let kp_out = keyed_permutation(input, round_key);

    let expanded = expansion_64_to_96(kp_out);

    let after_sa = substitution_layer(&expanded, true);

    let after_p = linear_permutation(after_sa);

    let mut sb_in = [0u16; 8];
    for i in 0..8 {
        sb_in[i] = ((after_p >> (8 * i)) & 0xFF) as u16;
    }
    let after_sb = substitution_layer(&sb_in, false);

    after_sb ^ round_key
}

fn keyed_permutation(data: u64, key: u64) -> u64 {
    let lo = data as u32;
    let hi = (data >> 32) as u32;
    let mut new_lo = 0u32;
    let mut new_hi = 0u32;
    for i in 0..32 {
        let mask = 1u32 << i;
        if (key as u32) & mask != 0 {
            // swap bits
            let b_lo = (lo >> i) & 1;
            let b_hi = (hi >> i) & 1;
            new_lo |= b_hi << i;
            new_hi |= b_lo << i;
        } else {
            new_lo |= lo & mask;
            new_hi |= hi & mask;
        }
    }
    ((new_hi as u64) << 32) | (new_lo as u64)
}


fn expansion_64_to_96(value: u64) -> [u16; 8] {
    let mut out = [0u16; 8];
    for i in 0..8 {
        let rotated = value.rotate_right((i * 8) as u32);
        out[i] = (rotated & 0x0FFF) as u16;
    }
    out
}

fn substitution_layer(input: &[u16; 8], first: bool) -> u64 {
    let pattern: [u8; 8] = if first {
        [1,2,1,2,2,1,2,1]
    } else {
        [2,2,1,1,2,2,1,1]
    };
    let mut acc = 0u64;
    for i in 0..8 {
        let b = match pattern[i] {
            1 => s1(input[i]),
            2 => s2(input[i]),
            _ => unreachable!(),
        } as u64;
        acc |= b << (8 * i);
    }
    acc
}

fn linear_permutation(x: u64) -> u64 {
    let mut y = 0u64;
    for i in 0..64 {
        let bit = (x >> (63 - i)) & 1;
        let tgt = 63 - P[i] as usize;
        y |= bit << tgt;
    }
    y
}
