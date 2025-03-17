use lab_1::crypto::utils::*;
use bitvec::prelude::*;

#[test]
fn test_bytes_to_bits() {
    let input = vec![0b10101010, 0b11001100];
    let expected = bitvec![1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0];
    assert_eq!(bytes_to_bits(&input), expected);
}

#[test]
fn test_bits_to_bytes() {
    let bits = bitvec![1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0];
    let expected = vec![0b10101010, 0b11001100];
    assert_eq!(bits_to_bytes(&bits), expected);
}

#[test]
fn test_shift_bits() {
    let input = vec![0b10101010, 0b11001100];
    let p_block = vec![2, 4, 6, 8, 10, 12, 14, 16, 1, 3, 5, 7, 9, 11, 13, 15];

    let result = shift_bits_little_endian(&input, &p_block, true, 1);

    let expected = vec![0b10101111, 0b10100000];

    assert_eq!(result, expected);
}


#[test]
fn test_shift_bits_little_endian() {
    let input = vec![0b10101010, 0b11001100];
    let p_block = vec![2, 4, 6, 8, 10, 12, 14, 16, 1, 3, 5, 7, 9, 11, 13, 15];
    let expected = vec![0b11111010, 0b00001010];



    assert_eq!(shift_bits_little_endian(&input, &p_block, false, 1), expected);
}

#[test]
fn test_shift_bits_simple() {
    let input = vec![0b10101010, 0b11001100];

    let p_block = vec![
        16, 15, 14, 13, 12, 11, 10, 9,
        8, 7, 6, 5, 4, 3, 2, 1
    ];

    let result = shift_bits_little_endian(&input, &p_block, true, 1);

    println!("Test input: {:08b} {:08b}", input[0], input[1]);
    println!("Result: {:08b} {:08b}", result[0], result[1]);

    let expected = vec![0b00110011, 0b01010101];
    assert_eq!(result, expected);
}
