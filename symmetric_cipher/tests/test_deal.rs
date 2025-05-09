use symmetric_cipher::crypto::cipher_traits::SymmetricCipher;
use symmetric_cipher::crypto::des::DES;
use symmetric_cipher::crypto::des_key_expansion::DesKeyExpansion;
use symmetric_cipher::crypto::des_transformation::DesTransformation;

#[test]
fn test_deal_encrypt_decrypt() {
    use symmetric_cipher::crypto::deal::DEAL;
    use symmetric_cipher::crypto::des::DES;

    let key = hex_literal::hex!(
        "13 34 57 79 9B BC DF F1
         13 34 57 79 9B BC DF F1
         13 34 57 79 9B BC DF F1"
    );
    let plaintext = hex_literal::hex!("01 23 45 67 89 AB CD EF");

    let des = DES::new(
        std::sync::Arc::new(DesKeyExpansion),
        std::sync::Arc::new(DesTransformation),
    );

    let mut deal = DEAL::new(des);
    deal.set_key(&key).unwrap();

    let ciphertext = deal.encrypt(&plaintext, &key);
    let decrypted = deal.decrypt(&ciphertext, &key);

    assert_eq!(decrypted, plaintext);
}
