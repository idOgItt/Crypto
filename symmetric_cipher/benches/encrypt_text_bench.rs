use criterion::{criterion_group, criterion_main, Criterion, BatchSize};
use symmetric_cipher::crypto::cipher_types::{CipherInput, CipherOutput, CipherMode, PaddingMode};
use symmetric_cipher::crypto::cipher_context::CipherContext;
use symmetric_cipher::crypto::des::DES;
use symmetric_cipher::crypto::deal::DEAL;
use symmetric_cipher::crypto::des_key_expansion::DesKeyExpansion;
use symmetric_cipher::crypto::des_transformation::DesTransformation;
use symmetric_cipher::crypto::cipher_traits::SymmetricCipher;
use std::sync::Arc;

fn bench_text_modes_and_paddings(c: &mut Criterion) {
    let text = "The quick brown fox jumps over the lazy dog. Symmetric encryption test string!";
    let data = text.as_bytes().to_vec();

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
            let bench_name_des = format!("DES text {}+{}", mode_name, pad_name);
            let bench_name_deal = format!("DEAL text {}+{}", mode_name, pad_name);

            let iv = match mode {
                CipherMode::ECB | CipherMode::RandomDelta => None,
                _ => Some(vec![0u8; 8]),
            };

            // DES
            let des_key = vec![0x01; 8];
            let des = DES::new(Arc::new(DesKeyExpansion), Arc::new(DesTransformation));
            let mut ctx_des = CipherContext::new(Box::new(des), mode, pad, iv.clone(), vec![]);
            ctx_des.set_key(&des_key).unwrap();

            c.bench_function(&bench_name_des, |b| {
                b.iter_batched(
                    || data.clone(),
                    |input| {
                        let mut out = CipherOutput::Buffer(Box::new(Vec::new()));
                        futures::executor::block_on(ctx_des.encrypt(CipherInput::Bytes(input), &mut out)).unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });

            // DEAL
            let deal_key = vec![0x01; 24];
            let base_des = DES::new(Arc::new(DesKeyExpansion), Arc::new(DesTransformation));
            let mut deal = DEAL::new(base_des);
            deal.set_key(&deal_key).unwrap();
            let mut ctx_deal = CipherContext::new(Box::new(deal), mode, pad, iv.clone(), vec![]);
            ctx_deal.set_key(&deal_key).unwrap();

            c.bench_function(&bench_name_deal, |b| {
                b.iter_batched(
                    || data.clone(),
                    |input| {
                        let mut out = CipherOutput::Buffer(Box::new(Vec::new()));
                        futures::executor::block_on(ctx_deal.encrypt(CipherInput::Bytes(input), &mut out)).unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group!(benches, bench_text_modes_and_paddings);
criterion_main!(benches);
