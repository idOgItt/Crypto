use symmetric_cipher::crypto::des_transformation::DesTransformation;
use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;

#[test]
fn test_f_function_example() {
    let r = hex_literal::hex!("F0AAF123");
    let k = hex_literal::hex!("1B02EFFC7072");
    let expected = hex_literal::hex!("847B4BC0");
    let out = DesTransformation.transform(&r, &k);
    assert_eq!(out, expected);
}
