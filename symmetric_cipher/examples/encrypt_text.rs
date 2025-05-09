use tokio;
use symmetric_cipher::crypto::cipher_types::{CipherInput, CipherOutput, CipherMode, PaddingMode};
use symmetric_cipher::crypto::cipher_context::CipherContext;
use symmetric_cipher::crypto::des::DES;
use symmetric_cipher::crypto::deal::DEAL;
use symmetric_cipher::crypto::des_key_expansion::DesKeyExpansion;
use symmetric_cipher::crypto::key_expansion::KeyExpansion;
use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;
use symmetric_cipher::crypto::cipher_traits::SymmetricCipher;
use symmetric_cipher::crypto::des_transformation::DesTransformation;

use std::sync::Arc;

fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let text = "The quick brown fox jumps over the lazy dog. Symmetric encryption test string!";
    let data = text.as_bytes().to_vec();

    let mode = CipherMode::CBC;
    let pad = PaddingMode::PKCS7;
    let iv = Some(vec![0u8; 8]);

    // === DES ===
    let des_key = random_bytes(8);
    let des = DES::new(
        Arc::new(DesKeyExpansion),
        Arc::new(DesTransformation),
    );
    let mut ctx_des = CipherContext::new(Box::new(des), mode, pad, iv.clone(), vec![]);
    ctx_des.set_key(&des_key).unwrap();

    let mut enc_out = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx_des.encrypt(CipherInput::Bytes(data.clone()), &mut enc_out).await?;
    let encrypted = match enc_out {
        CipherOutput::Buffer(b) => *b,
        _ => unreachable!(),
    };

    let mut dec_out = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx_des.decrypt(CipherInput::Bytes(encrypted.clone()), &mut dec_out).await?;
    let decrypted = match dec_out {
        CipherOutput::Buffer(b) => *b,
        _ => unreachable!(),
    };

    assert_eq!(data, decrypted);
    println!("DES CBC+PKCS7 OK");

    // === DEAL ===
    let deal_key = random_bytes(24);
    let des_base = DES::new(
        Arc::new(DesKeyExpansion),
        Arc::new(DesTransformation),
    );
    let mut deal = DEAL::new(des_base);
    deal.set_key(&deal_key).unwrap();

    let mut ctx_deal = CipherContext::new(Box::new(deal), mode, pad, iv.clone(), vec![]);
    ctx_deal.set_key(&deal_key).unwrap();

    let mut enc_out = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx_deal.encrypt(CipherInput::Bytes(data.clone()), &mut enc_out).await?;
    let encrypted = match enc_out {
        CipherOutput::Buffer(b) => *b,
        _ => unreachable!(),
    };

    let mut dec_out = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx_deal.decrypt(CipherInput::Bytes(encrypted.clone()), &mut dec_out).await?;
    let decrypted = match dec_out {
        CipherOutput::Buffer(b) => *b,
        _ => unreachable!(),
    };

    assert_eq!(data, decrypted);
    println!("DEAL CBC+PKCS7 OK");

    Ok(())
}
