#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use symmetric_cipher::crypto::cipher_context::CipherContext;
    use super::*;
    use symmetric_cipher::crypto::des::DES;
    use symmetric_cipher::crypto::des_key_expansion::DesKeyExpansion;
    use symmetric_cipher::crypto::des_transformation::DesTransformation;
    use symmetric_cipher::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher};
    use symmetric_cipher::crypto::cipher_types::{CipherInput, CipherMode, CipherOutput, PaddingMode};

    #[test]
    fn test_des_nist_vector() {
        let key = hex_literal::hex!("13 34 57 79 9B BC DF F1");
        let plaintext = hex_literal::hex!("01 23 45 67 89 AB CD EF");
        let expected_ciphertext = hex_literal::hex!("73 D3 B6 CE E5 D2 A7 13");

        let des = DES::new(
            Arc::new(DesKeyExpansion),
            Arc::new(DesTransformation),
        );

        let mut des = des;
        des.set_key(&key).unwrap();

        let ciphertext = des.encrypt(&plaintext);
        assert_eq!(ciphertext, expected_ciphertext);

        let decrypted = des.decrypt(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_des_cbc_ansi_x923_encrypt_decrypt() {
        let key = b"12345678"; // 8 байт для DES
        let iv = Some(vec![0u8; 8]); // IV нужен для CBC
        let plaintext = b"Hello, world!\n";
    
        let des = DES::new(
            Arc::new(DesKeyExpansion),
            Arc::new(DesTransformation),
        );
        let mut ctx = CipherContext::new(
            Box::new(des),
            CipherMode::CBC,
            PaddingMode::ANSI_X923,
            iv.clone(),
            vec![], // дополнительные параметры (например, ключи раундов)
        );
    
        ctx.set_key(key).unwrap();
    
        // Шифруем
        let mut encrypted_buf = Box::new(Vec::new());
        let mut encrypted_output = CipherOutput::Buffer(encrypted_buf);
        ctx.encrypt(CipherInput::Bytes(plaintext.to_vec()), &mut encrypted_output)
            .await
            .unwrap();
    
        let encrypted = if let CipherOutput::Buffer(buf) = encrypted_output {
            *buf
        } else {
            panic!("Expected buffer output");
        };
    
        // Дешифруем
        let mut decrypted_buf = Box::new(Vec::new());
        let mut decrypted_output = CipherOutput::Buffer(decrypted_buf);
        ctx.decrypt(CipherInput::Bytes(encrypted.clone()), &mut decrypted_output)
            .await
            .unwrap();
    
        let decrypted = if let CipherOutput::Buffer(buf) = decrypted_output {
            *buf
        } else {
            panic!("Expected buffer output");
        };
    
        assert_eq!(decrypted, plaintext);
    }

}
