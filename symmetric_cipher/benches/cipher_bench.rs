use std::time::{Duration, Instant};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::runtime::Runtime;

use rand::RngCore;
use std::io::Write;
use tempfile::NamedTempFile;
use symmetric_cipher::crypto::cipher_context::CipherContext;
use symmetric_cipher::crypto::cipher_traits::{CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds};
use symmetric_cipher::crypto::cipher_types::{CipherInput, CipherMode, CipherOutput, PaddingMode};

struct IdentityCipher;

impl SymmetricCipher for IdentityCipher {
    fn set_key(&mut self, _: &[u8]) -> Result<(), &'static str> { Ok(()) }
}
impl CipherAlgorithm for IdentityCipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
}
impl SymmetricCipherWithRounds for IdentityCipher {
    fn set_key_with_rounds(&mut self, _: &[u8]) {}
    fn encrypt_block(&self, block: &[u8], _: &[u8]) -> Vec<u8> { block.to_vec() }
    fn decrypt_block(&self, block: &[u8], _: &[u8]) -> Vec<u8> { block.to_vec() }
    fn block_size(&self) -> usize { 8 }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        todo!()
    }
}

fn bench_large_file(c: &mut Criterion) {
    let mut input_file = NamedTempFile::new().unwrap();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut rng = rand::rng();
    for _ in 0..1024 {
        rng.fill_bytes(&mut buffer);
        input_file.write_all(&buffer).unwrap();
    }
    let input_path = input_file.path().to_string_lossy().into_owned();

    let mut group = c.benchmark_group("File Encryption 1GB");
    group.sample_size(15);
    group.measurement_time(Duration::from_secs(600));

    let rt = Runtime::new().unwrap();

    group.bench_function(
        BenchmarkId::new("ECB File Encrypt", "1GB"),
        move |b| {
            let input = input_path.clone();
            b.to_async(&rt)
                .iter(move || {
                    let input = input.clone();
                    async move {
                        let ctx = CipherContext::new(
                            Box::new(IdentityCipher),
                            CipherMode::ECB,
                            PaddingMode::PKCS7,
                            None,
                            vec![0u8; 8],
                        );

                        let output_file = NamedTempFile::new().unwrap();
                        let output_path = output_file.path().to_string_lossy().into_owned();

                        let start = Instant::now();
                        ctx.encrypt(
                            CipherInput::File(input.clone()),
                            &mut CipherOutput::File(output_path),
                        )
                            .await
                            .unwrap();
                        println!("One encrypt duration: {:?}", start.elapsed());
                    }
                })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_large_file);
criterion_main!(benches);
