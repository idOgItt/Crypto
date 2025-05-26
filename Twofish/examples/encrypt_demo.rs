use std::fs;
use tokio;

use rand::SeedableRng;
use rand::{rngs::StdRng, RngCore};

use twofish::crypto::twofish::Twofish;
use twofish::crypto::key_schedule::expand_key;
use twofish::crypto::sboxes::{q0, q1};
use twofish::crypto::mds::mds_multiply;

use symmetric_cipher::crypto::cipher_context::CipherContext;
use symmetric_cipher::crypto::cipher_traits::{
    CipherAlgorithm, SymmetricCipher, SymmetricCipherWithRounds
};
use symmetric_cipher::crypto::cipher_types::{
    CipherInput, CipherMode, CipherOutput, PaddingMode,
};

fn random_key(len: usize, rng: &mut impl RngCore) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let key_sizes = [16usize, 24, 32];

    let modes = [
        CipherMode::ECB, CipherMode::CBC, CipherMode::PCBC,
        CipherMode::CFB, CipherMode::OFB, CipherMode::CTR,
        CipherMode::RandomDelta,
    ];
    let paddings = [
        PaddingMode::Zeros, PaddingMode::ANSI_X923,
        PaddingMode::PKCS7, PaddingMode::ISO10126,
    ];

    // --------------------------------------------------------
    // 0) Key schedule & single-block Twofish demo
    // --------------------------------------------------------
    println!("=== Key schedule & single-block Twofish demo ===");
    let key128 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];
    let round_keys = expand_key(&key128);
    println!(" First round key: 0x{:08x}", round_keys[0]);
    println!(" Total round keys: {}", round_keys.len());

    let block = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut cipher = Twofish::new(&key128);

    let round_keys_bytes = cipher.export_round_keys().unwrap();
    println!(" First round key (bytes): {:02x?}", &round_keys_bytes[0..4]);

    let enc_vec = cipher.encrypt(&block);
    let dec_vec = cipher.decrypt(&enc_vec);
    println!(" Plaintext block: {:02x?}", block);
    println!(" Encrypted block: {:02x?}", enc_vec);
    println!(" Decrypted block: {:02x?}", dec_vec);
    assert_eq!(dec_vec, block);

    // --------------------------------------------------------
    // 1) Q-box demo
    // --------------------------------------------------------
    println!("\n=== Q-box demo ===");
    for &x in &[0x00u8, 0x53, 0x7F, 0xAA, 0xFF] {
        let y0 = q0(x);
        let y1 = q1(x);
        println!("  Q0(0x{:02x}) = 0x{:02x}", x, y0);
        println!("  Q1(0x{:02x}) = 0x{:02x}", x, y1);
    }

    // --------------------------------------------------------
    // 2) MDS demo
    // --------------------------------------------------------
    println!("\n=== MDS transformation demo ===");
    for &input in &[0x00000000u32, 0x01234567, 0x89ABCDEF, 0xFFFFFFFF] {
        let output = mds_multiply(input);
        println!("  MDS(0x{:08x}) = 0x{:08x}", input, output);
    }

    // --------------------------------------------------------
    // 3) Test vectors verification
    // --------------------------------------------------------
    println!("\n=== Test vectors verification ===");

    // 128-bit key test vector
    let test_key_128 = key128;
    let test_plain_128 = block;
    let expected_cipher_128 = [
        0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
        0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A
    ];

    let cipher_128 = Twofish::new(&test_key_128);
    let result_128 = cipher_128.encrypt(&test_plain_128);
    println!(" 128-bit key test: {:?}", result_128 == expected_cipher_128);

    // 192-bit key test vector
    let test_key_192 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    ];
    let expected_cipher_192 = [
        0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44,
        0x8F, 0x28, 0x9D, 0x02, 0xB9, 0x04, 0x1F, 0xDB
    ];

    let cipher_192 = Twofish::new(&test_key_192);
    let result_192 = cipher_192.encrypt(&test_plain_128);
    println!(" 192-bit key test: {:?}", result_192 == expected_cipher_192);

    // 256-bit key test vector
    let test_key_256 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ];
    let expected_cipher_256 = [
        0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75,
        0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05
    ];

    let cipher_256 = Twofish::new(&test_key_256);
    let result_256 = cipher_256.encrypt(&test_plain_128);
    println!(" 256-bit key test: {:?}", result_256 == expected_cipher_256);

    // --------------------------------------------------------
    // 4) Random data encryption: modes, key sizes
    // --------------------------------------------------------
    println!("\n=== Random data demo ===");
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let data: Vec<u8> = (0..1024).map(|_| rng.next_u32() as u8).collect();

    for &ks in &key_sizes {
        let key = random_key(ks, &mut rng);
        for &mode in &modes {
            for &pad in &paddings {
                let iv = if matches!(mode, CipherMode::ECB | CipherMode::RandomDelta) {
                    None
                } else {
                    Some(vec![0u8; 16]) // Twofish использует 16-байтные блоки
                };
                let mut ctx = CipherContext::new(
                    Box::new(Twofish::new(&key)) as _,
                    mode, pad, iv.clone(), Vec::new()
                );
                ctx.set_key(&key).unwrap();

                // encrypt
                let mut out_enc = CipherOutput::Buffer(Box::new(Vec::new()));
                ctx.encrypt(CipherInput::Bytes(data.clone()), &mut out_enc).await.unwrap();
                let cipher = out_enc.as_buffer().clone();

                // decrypt
                let mut out_dec = CipherOutput::Buffer(Box::new(Vec::new()));
                ctx.decrypt(CipherInput::Bytes(cipher.clone()), &mut out_dec).await.unwrap();
                let plain = out_dec.as_buffer();
                assert_eq!(plain, &data);

                println!(
                    "key={}b {}+{} OK",
                    ks * 8,
                    format!("{:?}", mode).to_lowercase(),
                    format!("{:?}", pad).to_lowercase()
                );
            }
        }
    }

    // --------------------------------------------------------
    // 5) File encryption/decryption demo
    // --------------------------------------------------------
    // Create output directory in the Twofish crate
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_dir = crate_dir.join("examples").join("output");
    std::fs::create_dir_all(&out_dir)?;
    println!("\n=== File demo ===");

    // Get the path to the workspace root (parent of twofish)
    let workspace_root = crate_dir.parent().unwrap_or(crate_dir);

    // Define files relative to workspace root
    let files = [
        "symmetric_cipher/examples/files/sample.txt",
        "symmetric_cipher/examples/files/image.png",
        "symmetric_cipher/examples/files/song.mp3",
        "symmetric_cipher/examples/files/video.mp4",
        "symmetric_cipher/examples/files/big.bin",
    ];

    for &input_path in &files {
        // Create absolute paths to input files
        let input = workspace_root.join(input_path);

        // Check if the file exists before trying to read it
        if !input.exists() {
            println!("File {} not found, skipping", input.display());
            continue;
        }

        let data = fs::read(&input)?;
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        let ext = input.extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();

        for &ks in &key_sizes {
            let key = random_key(ks, &mut rng);
            for &mode in &modes {
                // Test just one padding mode to save time
                let pad = PaddingMode::PKCS7;
                let iv = if matches!(mode, CipherMode::ECB | CipherMode::RandomDelta) {
                    None
                } else {
                    Some(vec![0u8; 16]) // 16-байтные блоки для Twofish
                };
                let mut ctx = CipherContext::new(
                    Box::new(Twofish::new(&key)) as _,
                    mode, pad, iv.clone(), Vec::new()
                );
                ctx.set_key(&key).unwrap();

                // Use out_dir to create absolute paths for output files
                let enc_path = out_dir.join(format!(
                    "{}_{}_twofish_{}.bin",
                    stem,
                    ks * 8,
                    format!("{:?}", mode).to_lowercase()
                ));
                let dec_path = out_dir.join(format!(
                    "{}_{}_twofish_{}_out{}",
                    stem,
                    ks * 8,
                    format!("{:?}", mode).to_lowercase(),
                    ext
                ));

                // Convert paths to strings
                let enc_path_str = enc_path.to_string_lossy().to_string();
                let dec_path_str = dec_path.to_string_lossy().to_string();

                // encrypt
                let mut out_enc = CipherOutput::File(enc_path_str.clone());
                ctx.encrypt(CipherInput::Bytes(data.clone()), &mut out_enc).await.unwrap();

                // decrypt
                let mut out_dec = CipherOutput::File(dec_path_str.clone());
                ctx.decrypt(CipherInput::File(enc_path_str.clone()), &mut out_dec).await.unwrap();

                // Verify the decrypted content matches the original
                let original = fs::read(&input)?;
                let decrypted = fs::read(dec_path)?;
                assert_eq!(decrypted, original);

                println!(
                    "File {} with key={}b {} OK",
                    input.file_name().unwrap_or_default().to_string_lossy(),
                    ks * 8,
                    format!("{:?}", mode).to_lowercase()
                );
            }
        }
    }

    // --------------------------------------------------------
    // 6) Performance test with different round counts
    // --------------------------------------------------------
    println!("\n=== Performance with different rounds ===");
    let perf_key = [0x55u8; 32];
    let perf_data = vec![0xAAu8; 1024 * 16]; // 16KB
    let cipher = Twofish::new(&perf_key);

    for rounds in [1, 4, 8, 12, 16] {
        let start = std::time::Instant::now();

        // Encrypt all blocks with specified rounds
        let mut encrypted = Vec::new();
        for chunk in perf_data.chunks(16) {
            encrypted.extend(cipher.encrypt_with_rounds(chunk, rounds));
        }

        let encrypt_time = start.elapsed();

        let start = std::time::Instant::now();

        // Decrypt all blocks
        let mut decrypted = Vec::new();
        for chunk in encrypted.chunks(16) {
            decrypted.extend(cipher.decrypt_with_rounds(chunk, rounds));
        }

        let decrypt_time = start.elapsed();

        assert_eq!(decrypted, perf_data);

        println!(
            " {} rounds: encrypt={:?}, decrypt={:?}",
            rounds, encrypt_time, decrypt_time
        );
    }

    Ok(())
}