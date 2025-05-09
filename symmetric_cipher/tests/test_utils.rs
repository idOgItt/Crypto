#[cfg(test)]
mod tests {
    use bitvec::prelude::*;
    use symmetric_cipher::crypto::cipher_types::PaddingMode;
    use symmetric_cipher::crypto::utils::*;

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

    #[test]
    fn test_apply_padding_zeros() {
        let data = vec![1, 2, 3];
        let padded = apply_padding(data.clone(), 8, PaddingMode::Zeros);
        assert_eq!(padded.len() % 8, 0);
        assert_eq!(&padded[..3], &data[..]);
        assert!(padded[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_apply_padding_pkcs7() {
        let data = vec![1, 2, 3];
        let padded = apply_padding(data.clone(), 8, PaddingMode::PKCS7);
        assert_eq!(padded.len() % 8, 0);
        let pad_value = padded.last().copied().unwrap();
        assert!(padded.ends_with(&vec![pad_value; pad_value as usize]));
    }

    #[test]
    fn test_apply_padding_ansi_x923() {
        let data = vec![1, 2, 3];
        let padded = apply_padding(data.clone(), 8, PaddingMode::ANSI_X923);
        assert_eq!(padded.len() % 8, 0);
        assert_eq!(padded.last().copied().unwrap(), 5);
        assert!(padded[padded.len() - 5..padded.len() - 1].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_apply_padding_iso10126() {
        let data = vec![1, 2, 3];
        let padded = apply_padding(data.clone(), 8, PaddingMode::ISO10126);
        assert_eq!(padded.len() % 8, 0);
        let pad_value = padded.last().copied().unwrap();
        assert_eq!(pad_value as usize, 5);
    }

    #[test]
    fn test_remove_padding_zeros() {
        let padded = vec![1, 2, 3, 0, 0];
        let unpadded = remove_padding(padded, PaddingMode::Zeros);
        assert_eq!(unpadded, vec![1, 2, 3]);
    }

    #[test]
    fn test_remove_padding_pkcs7() {
        let data = vec![1, 2, 3];
        let padded = apply_padding(data.clone(), 8, PaddingMode::PKCS7);
        let unpadded = remove_padding(padded, PaddingMode::PKCS7);
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_remove_padding_ansi_x923() {
        let data = vec![1, 2, 3];
        let padded = apply_padding(data.clone(), 8, PaddingMode::ANSI_X923);
        let unpadded = remove_padding(padded, PaddingMode::ANSI_X923);
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_remove_padding_iso10126() {
        let data = vec![1, 2, 3];
        let padded = apply_padding(data.clone(), 8, PaddingMode::ISO10126);
        let unpadded = remove_padding(padded, PaddingMode::ISO10126);
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_normalize_block_encrypt() {
        let data = vec![1, 2, 3];
        let normalized = normalize_block(data.clone(), 8, true, PaddingMode::PKCS7);
        assert_eq!(normalized.len(), 8);
        assert_eq!(&normalized[..3], &data[..]);
    }

    #[test]
    fn test_normalize_block_decrypt() {
        let data = vec![1, 2, 3];
        let normalized = normalize_block(data.clone(), 8, false, PaddingMode::PKCS7);
        assert_eq!(normalized.len(), 8);
        assert_eq!(&normalized[..3], &data[..]);
        assert!(normalized[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_full_padding_block_removal_pkcs7() {
        let block_size = 8;
        let data = vec![11, 22, 33, 44, 55, 66, 77, 88];

        let padded = apply_padding(data.clone(), block_size, PaddingMode::PKCS7);
        assert_eq!(padded.len(), 16); // должен добавиться блок паддинга
        let pad_byte = padded.last().copied().unwrap();
        assert_eq!(pad_byte as usize, block_size);
        assert!(padded[8..].iter().all(|&b| b == pad_byte));

        let unpadded = remove_padding(padded, PaddingMode::PKCS7);
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_full_padding_block_removal_ansi_x923() {
        let block_size = 8;
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let padded = apply_padding(data.clone(), block_size, PaddingMode::ANSI_X923);
        assert_eq!(padded.len(), 16);
        let pad_len = padded.last().copied().unwrap() as usize;
        assert_eq!(pad_len, block_size);
        assert!(padded[8..15].iter().all(|&b| b == 0));
        assert_eq!(padded[15], block_size as u8);

        let unpadded = remove_padding(padded, PaddingMode::ANSI_X923);
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_full_padding_block_removal_iso10126() {
        let block_size = 8;
        let data = vec![99, 88, 77, 66, 55, 44, 33, 22];

        let padded = apply_padding(data.clone(), block_size, PaddingMode::ISO10126);
        assert_eq!(padded.len(), 16);
        let pad_len = padded.last().copied().unwrap() as usize;
        assert_eq!(pad_len, block_size);

        let unpadded = remove_padding(padded, PaddingMode::ISO10126);
        assert_eq!(unpadded, data);
    }
}