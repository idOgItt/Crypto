use tokio;
use std::fs;
use std::path::Path;

use symmetric_cipher::crypto::cipher_types::{CipherInput, CipherOutput, CipherMode, PaddingMode};
use symmetric_cipher::crypto::cipher_context::CipherContext;
use symmetric_cipher::crypto::des::DES;
use symmetric_cipher::crypto::deal::DEAL;
use symmetric_cipher::crypto::des_key_expansion::DesKeyExpansion;
use symmetric_cipher::crypto::key_expansion::KeyExpansion;
use symmetric_cipher::crypto::encryption_transformation::EncryptionTransformation;

use std::sync::Arc;
use symmetric_cipher::crypto::cipher_traits::SymmetricCipher;
use symmetric_cipher::crypto::des_transformation::DesTransformation;

fn random_key(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let files = [
        "examples/files/sample.txt",
        "examples/files/image.png",
        "examples/files/song.mp3",
        "examples/files/video.mp4",
        "examples/files/big.bin",
    ];

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

    for input in &files {
        println!("\n--- File: {} ---", input);
        let data = fs::read(input)?;
        println!("Read {} bytes", data.len());

        let stem = Path::new(input)
            .file_stem()
            .unwrap()
            .to_string_lossy();
        let ext = Path::new(input)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();

        for &mode in &modes {
            for &pad in &paddings {
                let mode_name = format!("{:?}", mode).to_lowercase();
                let pad_name = format!("{:?}", pad).to_lowercase();

                let iv = match mode {
                    CipherMode::ECB | CipherMode::RandomDelta => None,
                    _ => Some(vec![0u8; 8]),
                };

                //
                // ==== DES ====
                //
                let des_key = random_key(8);
                let des = DES::new(
                    Arc::new(DesKeyExpansion) as Arc<dyn KeyExpansion + Send + Sync>,
                    Arc::new(DesTransformation) as Arc<dyn EncryptionTransformation + Send + Sync>,
                );
                let mut ctx_des = CipherContext::new(
                    Box::new(des),
                    mode,
                    pad,
                    iv.clone(),
                    vec![],
                );
                ctx_des.set_key(&des_key).expect("Failed to set DES key");

                let enc_des = format!(
                    "examples/output/{}_{}_{}_des.bin",
                    stem, mode_name, pad_name
                );
                let mut out_des = CipherOutput::File(enc_des.clone());
                ctx_des.encrypt(
                    CipherInput::Bytes(data.clone()),
                    &mut out_des,
                ).await?;
                println!("DES {}+{} encrypted -> {}", mode_name, pad_name, enc_des);

                let dec_des = format!(
                    "examples/output/{}_{}_{}_des_out{}",
                    stem, mode_name, pad_name, ext
                );
                let mut out_des_dec = CipherOutput::File(dec_des.clone());
                ctx_des.decrypt(
                    CipherInput::File(enc_des.clone()),
                    &mut out_des_dec,
                ).await?;
                println!("DES {}+{} decrypted -> {}", mode_name, pad_name, dec_des);

                assert_eq!(fs::read(input)?, fs::read(&dec_des)?);
                println!("DES {}+{} OK", mode_name, pad_name);

                //
                // ==== DEAL ====
                //
                let deal_key = random_key(24);
                let des_for_deal = DES::new(
                    Arc::new(DesKeyExpansion) as Arc<dyn KeyExpansion + Send + Sync>,
                    Arc::new(DesTransformation) as Arc<dyn EncryptionTransformation + Send + Sync>,
                );
                let mut deal = DEAL::new(des_for_deal);
                deal.set_key(&deal_key).expect("Failed to set DEAL key");

                let mut ctx_deal = CipherContext::new(
                    Box::new(deal),
                    mode,
                    pad,
                    iv.clone(),
                    vec![],
                );
                ctx_deal.set_key(&deal_key).expect("Failed to set DEAL key in context");

                let enc_deal = format!(
                    "examples/output/{}_{}_{}_deal.bin",
                    stem, mode_name, pad_name
                );
                let mut out_deal = CipherOutput::File(enc_deal.clone());
                ctx_deal.encrypt(
                    CipherInput::Bytes(data.clone()),
                    &mut out_deal,
                ).await?;
                println!("DEAL {}+{} encrypted -> {}", mode_name, pad_name, enc_deal);

                let dec_deal = format!(
                    "examples/output/{}_{}_{}_deal_out{}",
                    stem, mode_name, pad_name, ext
                );
                let mut out_deal_dec = CipherOutput::File(dec_deal.clone());
                ctx_deal.decrypt(
                    CipherInput::File(enc_deal.clone()),
                    &mut out_deal_dec,
                ).await?;
                println!("DEAL {}+{} decrypted -> {}", mode_name, pad_name, dec_deal);

                assert_eq!(fs::read(input)?, fs::read(&dec_deal)?);
                println!("DEAL {}+{} OK", mode_name, pad_name);
            }
        }
    }

    Ok(())
}
