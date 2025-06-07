use symmetric_cipher::crypto::des_key_expansion::DesKeyExpansion;
use symmetric_cipher::crypto::key_expansion::KeyExpansion;

#[test]
fn test_key_expansion_round1() {
    let key = hex_literal::hex!("133457799BBCDFF1");
    let expected_k1 = hex_literal::hex!("3E40F3D8FDE5");
    let k1 = DesKeyExpansion.generate_round_keys(&key)[0].clone();
    assert_eq!(k1, expected_k1);
}
