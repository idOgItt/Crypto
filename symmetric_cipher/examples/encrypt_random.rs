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
    let data = random_bytes(1024);

    let modes = [
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::PCBC,
        CipherMode::CFB,
        CipherMode::OFB,
        CipherMode::CTR,
        CipherMode::RandomDelta,
    ];

    let paddings = [
        PaddingMode::Zeros,
        PaddingMode::ANSI_X923,
        PaddingMode::PKCS7,
        PaddingMode::ISO10126,
    ];

    for &mode in &modes {
        for &pad in &paddings {
            let mode_name = format!("{:?}", mode).to_lowercase();
            let pad_name = format!("{:?}", pad).to_lowercase();

            let iv = match mode {
                CipherMode::ECB | CipherMode::RandomDelta => None,
                _ => Some(vec![0u8; 8]),
            };

            //
            // === DES ===
            //
            let des_key = random_bytes(8);
            let des = DES::new(
                Arc::new(DesKeyExpansion),
                Arc::new(DesTransformation),
            );
            let mut ctx_des = CipherContext::new(Box::new(des), mode, pad, iv.clone(), vec![]);
            ctx_des.set_key(&des_key).unwrap();

            let mut out = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx_des.encrypt(CipherInput::Bytes(data.clone()), &mut out).await?;
            let ciphertext = match out {
                CipherOutput::Buffer(b) => *b,
                _ => unreachable!(),
            };

            let mut decrypted = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx_des.decrypt(CipherInput::Bytes(ciphertext.clone()), &mut decrypted).await?;
            let plain = match decrypted {
                CipherOutput::Buffer(b) => *b,
                _ => unreachable!(),
            };

            assert_eq!(data, plain, "DES failed for {mode_name}+{pad_name}");
            println!("DES {}+{} OK", mode_name, pad_name);

            //
            // === DEAL ===
            //
            let deal_key = random_bytes(24);
            let base_des = DES::new(
                Arc::new(DesKeyExpansion),
                Arc::new(DesTransformation),
            );
            let mut deal = DEAL::new(base_des);
            deal.set_key(&deal_key).unwrap();

            let mut ctx_deal = CipherContext::new(Box::new(deal), mode, pad, iv.clone(), vec![]);
            ctx_deal.set_key(&deal_key).unwrap();

            let mut out = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx_deal.encrypt(CipherInput::Bytes(data.clone()), &mut out).await?;
            let ciphertext = match out {
                CipherOutput::Buffer(b) => *b,
                _ => unreachable!(),
            };

            let mut decrypted = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx_deal.decrypt(CipherInput::Bytes(ciphertext.clone()), &mut decrypted).await?;
            let plain = match decrypted {
                CipherOutput::Buffer(b) => *b,
                _ => unreachable!(),
            };

            assert_eq!(data, plain, "DEAL failed for {mode_name}+{pad_name}");
            println!("DEAL {}+{} OK", mode_name, pad_name);
        }
    }

    Ok(())
}
