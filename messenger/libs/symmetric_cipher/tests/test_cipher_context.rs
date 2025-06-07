use rand::{rng, RngCore};
use std::fs::File;
use std::io::{Read, Write};
use symmetric_cipher::crypto::cipher_context::CipherContext;
use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds,
};
use symmetric_cipher::crypto::cipher_types::{CipherInput, CipherMode, CipherOutput, PaddingMode};
use tempfile::NamedTempFile;

struct IdentityCipher;

impl SymmetricCipher for IdentityCipher {
    fn set_key(&mut self, _: &[u8]) -> Result<(), &'static str> {
        Ok(())
    }
}

impl CipherAlgorithm for IdentityCipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

impl SymmetricCipherWithRounds for IdentityCipher {
    fn set_key_with_rounds(&mut self, _key: &[u8]) {}

    fn encrypt_block(&self, block: &[u8], _round_key: &[u8]) -> Vec<u8> {
        block.to_vec()
    }

    fn decrypt_block(&self, block: &[u8], _round_key: &[u8]) -> Vec<u8> {
        block.to_vec()
    }

    fn block_size(&self) -> usize {
        8
    }

    fn export_round_keys(&self) -> Option<Vec<u8>> {
        todo!()
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rng();
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

async fn run_encrypt_decrypt(mode: CipherMode, padding: PaddingMode, data_len: usize) {
    let key = random_bytes(8);
    let iv = Some(random_bytes(8));
    let data = random_bytes(data_len);

    let algorithm = Box::new(IdentityCipher);
    let ctx = CipherContext::new(algorithm, mode, padding, iv, key);

    let mut out_buf = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.encrypt(CipherInput::Bytes(data.clone()), &mut out_buf)
        .await
        .unwrap();

    let ciphertext = out_buf.as_buffer();

    let mut dec_buf = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.decrypt(CipherInput::Bytes(ciphertext.clone()), &mut dec_buf)
        .await
        .unwrap();

    let decrypted = dec_buf.as_buffer();

    if decrypted.len() < data.len() {
        panic!(
            "\n[FAIL: Short Output]\nMode: {:?}\nPadding: {:?}\nDataLen: {}\nDecryptedLen: {}\nCiphertextLen: {}\nOriginal: {:?}\nDecrypted: {:?}\n",
            mode,
            padding,
            data.len(),
            decrypted.len(),
            ciphertext.len(),
            &data,
            &decrypted
        );
    }

    if &data[..] != &decrypted[..data.len()] {
        panic!(
            "\n[FAIL: Mismatch]\nMode: {:?}\nPadding: {:?}\nDataLen: {}\nDecryptedLen: {}\nCiphertextLen: {}\nOriginal: {:?}\nDecrypted: {:?}\n",
            mode,
            padding,
            data.len(),
            decrypted.len(),
            ciphertext.len(),
            &data,
            &decrypted
        );
    }
}

#[tokio::test]
async fn test_encrypt_decrypt_all_modes_and_paddings_randomized() {
    let modes = [
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::CFB,
        CipherMode::OFB,
        CipherMode::CTR,
        CipherMode::PCBC,
        CipherMode::RandomDelta,
    ];
    let paddings = [
        PaddingMode::PKCS7,
        PaddingMode::ANSI_X923,
        PaddingMode::ISO10126,
    ];
    let sizes = [0, 1, 7, 8, 9, 15, 16, 31, 32, 64];
    for &mode in &modes {
        for &pad in &paddings {
            if matches!(mode, CipherMode::CFB | CipherMode::OFB | CipherMode::CTR)
                && !matches!(pad, PaddingMode::Zeros)
            {
                continue;
            }

            for &len in &sizes {
                run_encrypt_decrypt(mode, pad, len).await;
            }
        }
    }
}

#[test]
fn test_set_key_arc_fail() {
    let mut ctx = CipherContext::new(
        Box::new(IdentityCipher),
        CipherMode::ECB,
        PaddingMode::Zeros,
        None,
        vec![0u8; 8],
    );
    let _clone = ctx.clone();
    let result = ctx.set_key(&[1, 2, 3]);
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_file_encryption_roundtrip() {
    let mut input_file = NamedTempFile::new().unwrap();
    write!(input_file, "exampledata").unwrap();

    let output_file = NamedTempFile::new().unwrap();
    let back_file = NamedTempFile::new().unwrap();

    let algorithm = Box::new(IdentityCipher);
    let ctx = CipherContext::new(
        algorithm,
        CipherMode::ECB,
        PaddingMode::PKCS7,
        Some(random_bytes(8)),
        random_bytes(8),
    );

    ctx.encrypt(
        CipherInput::File(input_file.path().to_string_lossy().to_string()),
        &mut CipherOutput::File(output_file.path().to_string_lossy().to_string()),
    )
    .await
    .unwrap();

    ctx.decrypt(
        CipherInput::File(output_file.path().to_string_lossy().to_string()),
        &mut CipherOutput::File(back_file.path().to_string_lossy().to_string()),
    )
    .await
    .unwrap();

    let mut result = String::new();
    File::open(back_file.path())
        .unwrap()
        .read_to_string(&mut result)
        .unwrap();
    assert_eq!(result, "exampledata");
}

trait BufferExt {
    fn as_buffer(&self) -> &Vec<u8>;
}

impl BufferExt for CipherOutput {
    fn as_buffer(&self) -> &Vec<u8> {
        match self {
            CipherOutput::Buffer(buf) => &**buf,
            _ => panic!("Expected buffer"),
        }
    }
}

#[tokio::test]
async fn test_decrypt_garbage_input_no_panic() {
    use symmetric_cipher::crypto::cipher_context::*;
    use symmetric_cipher::crypto::cipher_traits::*;
    use symmetric_cipher::crypto::cipher_types::*;

    let garbage: Vec<u8> = (0..31).map(|_| rand::random()).collect();
    let ctx = CipherContext::new(
        Box::new(IdentityCipher),
        CipherMode::CBC,
        PaddingMode::PKCS7,
        Some(vec![0u8; 8]),
        vec![0u8; 8],
    );

    let result = ctx
        .decrypt(
            CipherInput::Bytes(garbage),
            &mut CipherOutput::Buffer(Box::new(Vec::new())),
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_empty_input_roundtrip() {
    let ctx = CipherContext::new(
        Box::new(IdentityCipher),
        CipherMode::ECB,
        PaddingMode::PKCS7,
        None,
        vec![0u8; 8],
    );

    let mut out = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.encrypt(CipherInput::Bytes(vec![]), &mut out)
        .await
        .unwrap();

    let mut back = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.decrypt(CipherInput::Bytes(out.as_buffer().clone()), &mut back)
        .await
        .unwrap();

    assert_eq!(back.as_buffer(), &vec![]);
}

#[tokio::test]
async fn test_deterministic_output_for_same_input() {
    let data = b"abcdefg".to_vec();
    let key = vec![1u8; 8];
    let iv = Some(vec![2u8; 8]);

    let ctx = CipherContext::new(
        Box::new(IdentityCipher),
        CipherMode::ECB,
        PaddingMode::Zeros,
        iv.clone(),
        key.clone(),
    );

    let mut out1 = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.encrypt(CipherInput::Bytes(data.clone()), &mut out1)
        .await
        .unwrap();

    let mut out2 = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.encrypt(CipherInput::Bytes(data), &mut out2)
        .await
        .unwrap();

    assert_eq!(out1.as_buffer(), out2.as_buffer());
}

#[tokio::test]
async fn test_empty_input_roundtrip_all_modes_and_paddings() {
    let all_modes = [
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::CFB,
        CipherMode::OFB,
        CipherMode::CTR,
        CipherMode::PCBC,
        CipherMode::RandomDelta,
    ];
    let all_paddings = [
        PaddingMode::PKCS7,
        PaddingMode::ANSI_X923,
        PaddingMode::ISO10126,
    ];

    for &mode in &all_modes {
        for &padding in &all_paddings {
            let ctx = CipherContext::new(
                Box::new(IdentityCipher),
                mode,
                padding,
                Some(vec![0u8; 8]),
                vec![0u8; 8],
            );

            let mut out = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx.encrypt(CipherInput::Bytes(vec![]), &mut out)
                .await
                .unwrap();

            let mut back = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx.decrypt(CipherInput::Bytes(out.as_buffer().clone()), &mut back)
                .await
                .unwrap();

            assert_eq!(
                back.as_buffer(),
                &vec![],
                "Failed on mode {:?} padding {:?}",
                mode,
                padding
            );
        }
    }
}

#[tokio::test]
async fn test_decrypt_garbage_input_no_panic_all_modes() {
    let all_modes = [
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::CFB,
        CipherMode::OFB,
        CipherMode::CTR,
        CipherMode::PCBC,
        CipherMode::RandomDelta,
    ];
    let all_paddings = [
        PaddingMode::Zeros,
        PaddingMode::PKCS7,
        PaddingMode::ANSI_X923,
        PaddingMode::ISO10126,
    ];

    for &mode in &all_modes {
        for &padding in &all_paddings {
            let garbage: Vec<u8> = (0..31).map(|_| rand::random()).collect();
            let ctx = CipherContext::new(
                Box::new(IdentityCipher),
                mode,
                padding,
                Some(vec![0u8; 8]),
                vec![0u8; 8],
            );

            let result = ctx
                .decrypt(
                    CipherInput::Bytes(garbage),
                    &mut CipherOutput::Buffer(Box::new(Vec::new())),
                )
                .await;

            assert!(
                result.is_ok(),
                "Garbage input decryption panicked on mode {:?} padding {:?}",
                mode,
                padding
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_file_encryption_roundtrip_all_modes_and_paddings_short_text() {
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let all_modes = [
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::CFB,
        CipherMode::OFB,
        CipherMode::CTR,
        CipherMode::PCBC,
        CipherMode::RandomDelta,
    ];
    let all_paddings = [
        PaddingMode::Zeros,
        PaddingMode::PKCS7,
        PaddingMode::ANSI_X923,
        PaddingMode::ISO10126,
    ];

    for &mode in &all_modes {
        for &padding in &all_paddings {
            let mut input_file = NamedTempFile::new().unwrap();
            write!(input_file, "exampledata").unwrap();

            let output_file = NamedTempFile::new().unwrap();
            let back_file = NamedTempFile::new().unwrap();

            let ctx = CipherContext::new(
                Box::new(IdentityCipher),
                mode,
                padding,
                Some(vec![0u8; 8]),
                vec![0u8; 8],
            );

            ctx.encrypt(
                CipherInput::File(input_file.path().to_string_lossy().to_string()),
                &mut CipherOutput::File(output_file.path().to_string_lossy().to_string()),
            )
            .await
            .unwrap();

            ctx.decrypt(
                CipherInput::File(output_file.path().to_string_lossy().to_string()),
                &mut CipherOutput::File(back_file.path().to_string_lossy().to_string()),
            )
            .await
            .unwrap();

            let mut result = String::new();
            File::open(back_file.path())
                .unwrap()
                .read_to_string(&mut result)
                .unwrap();

            assert_eq!(
                result, "exampledata",
                "Mismatch on mode {:?} padding {:?}\nGot: {:?}",
                mode, padding, result
            );
        }
    }
}

#[tokio::test]
async fn test_deterministic_output_all_modes_and_paddings() {
    let data = b"abcdefg".to_vec();
    let key = vec![1u8; 8];
    let iv = Some(vec![2u8; 8]);

    let all_modes = [
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::CFB,
        CipherMode::OFB,
        CipherMode::CTR,
        CipherMode::PCBC,
        CipherMode::RandomDelta,
    ];
    let all_paddings = [
        PaddingMode::Zeros,
        PaddingMode::PKCS7,
        PaddingMode::ANSI_X923,
    ];

    for &mode in &all_modes {
        for &padding in &all_paddings {
            let ctx = CipherContext::new(
                Box::new(IdentityCipher),
                mode,
                padding,
                iv.clone(),
                key.clone(),
            );

            let mut out1 = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx.encrypt(CipherInput::Bytes(data.clone()), &mut out1)
                .await
                .unwrap();

            let mut out2 = CipherOutput::Buffer(Box::new(Vec::new()));
            ctx.encrypt(CipherInput::Bytes(data.clone()), &mut out2)
                .await
                .unwrap();

            assert_eq!(
                out1.as_buffer(),
                out2.as_buffer(),
                "Mismatch in deterministic output on mode {:?} padding {:?}",
                mode,
                padding
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_large_file_encryption_roundtrip_all_modes_and_paddings() {
    use rand::RngCore;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let sizes = [1024 * 1024, 5 * 1024 * 1024, 5 * 1024 * 1024 + 3];
    let all_modes = [
        CipherMode::ECB,
        CipherMode::CBC,
        CipherMode::CFB,
        CipherMode::OFB,
        CipherMode::CTR,
        CipherMode::PCBC,
        CipherMode::RandomDelta,
    ];
    let all_paddings = [
        PaddingMode::Zeros,
        PaddingMode::PKCS7,
        PaddingMode::ANSI_X923,
        PaddingMode::ISO10126,
    ];

    for &mode in &all_modes {
        for &padding in &all_paddings {
            for &size in &sizes {
                let mut input_file = NamedTempFile::new().unwrap();
                let mut data = vec![0u8; size];
                rand::rng().fill_bytes(&mut data);
                input_file.write_all(&data).unwrap();

                let output_file = NamedTempFile::new().unwrap();
                let back_file = NamedTempFile::new().unwrap();

                let ctx = CipherContext::new(
                    Box::new(IdentityCipher),
                    mode,
                    padding,
                    Some(vec![0u8; 8]),
                    vec![0u8; 8],
                );

                ctx.encrypt(
                    CipherInput::File(input_file.path().to_string_lossy().to_string()),
                    &mut CipherOutput::File(output_file.path().to_string_lossy().to_string()),
                )
                .await
                .unwrap();

                ctx.decrypt(
                    CipherInput::File(output_file.path().to_string_lossy().to_string()),
                    &mut CipherOutput::File(back_file.path().to_string_lossy().to_string()),
                )
                .await
                .unwrap();

                let mut result = Vec::new();
                File::open(back_file.path())
                    .unwrap()
                    .read_to_end(&mut result)
                    .unwrap();

                assert_eq!(
                    result.len(),
                    data.len(),
                    "\n[FAIL: Length mismatch]\nMode: {:?}\nPadding: {:?}\nSize: {}\nExpected: {}\nActual:   {}\n",
                    mode,
                    padding,
                    size,
                    data.len(),
                    result.len()
                );
            }
        }
    }
}
