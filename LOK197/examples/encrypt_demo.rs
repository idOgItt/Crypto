use std::fs;
use tokio;

use rand::SeedableRng;
use rand::{rngs::StdRng, RngCore};

use LOK197::crypto::f_function::round_function;
use LOK197::crypto::key_schedule::expand_key;
use LOK197::crypto::loki97::Loki97Cipher;
use LOK197::crypto::sboxes::{s1, s2};

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
    // 0) Key schedule & single-block LOK197 demo
    // --------------------------------------------------------
    println!("=== Key schedule & single-block LOK197 demo ===");
    let key128 = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let round_keys = expand_key(&key128);
    println!(" First round key: {:016x}", round_keys[0]);

    // 128-bit (16-byte) block для тестирования
    let block = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    ];

    let mut cipher = Loki97Cipher::new(&key128);

    let round_keys_bytes = cipher.export_round_keys().unwrap();
    println!(" First round key (bytes): {:02x?}", &round_keys_bytes[0..8]);

    // Encrypt and decrypt
    let enc_vec = cipher.encrypt(&block);
    let dec_vec = cipher.decrypt(&enc_vec);
    println!(" Plaintext block: {:02x?}", block);
    println!(" Encrypted block: {:02x?}", enc_vec);
    println!(" Decrypted block: {:02x?}", dec_vec);
    assert_eq!(dec_vec, block);

    // --------------------------------------------------------
    // 1) S-box demo
    // --------------------------------------------------------
    println!("\n=== S-box demo ===");
    for &x in &[0x00u16, 0x53, 0x7f, 0xAA, 0xFF] {
        let y1 = s1(x);
        let y2 = s2(x);
        println!("  S1(0x{:04x}) = 0x{:02x}", x, y1);
        println!("  S2(0x{:04x}) = 0x{:02x}", x, y2);
    }

    // --------------------------------------------------------
    // 2) Round function demo
    // --------------------------------------------------------
    println!("\n=== Round function demo ===");
    for &input in &[0x0000000000000000, 0x0123456789ABCDEF, 0xFFFFFFFFFFFFFFFF] {
        for &key in &[0x0000000000000000, 0xFEDCBA9876543210, 0xFFFFFFFFFFFFFFFF] {
            let output = round_function(input, key);
            println!("  f(0x{:016x}, 0x{:016x}) = 0x{:016x}", input, key, output);
        }
    }

    // --------------------------------------------------------
    // 3) Random data encryption: modes, key sizes
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
                    Some(vec![0u8; 16])
                };
                let mut ctx = CipherContext::new(
                    Box::new(Loki97Cipher::new(&key)) as _,
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
    // 4) File encryption/decryption demo
    // --------------------------------------------------------
    // Create output directory in the LOK197 crate
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_dir = crate_dir.join("examples").join("output");
    std::fs::create_dir_all(&out_dir)?;
    println!("\n=== File demo ===");

    // Get the path to the workspace root (parent of LOK197)
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
                    Some(vec![0u8; 16]) // 16-байтные блоки для 128-битного Loki97
                };
                let mut ctx = CipherContext::new(
                    Box::new(Loki97Cipher::new(&key)) as _,
                    mode, pad, iv.clone(), Vec::new()
                );
                ctx.set_key(&key).unwrap();

                // Use out_dir to create absolute paths for output files
                let enc_path = out_dir.join(format!(
                    "{}_{}_lok197_{}.bin",
                    stem,
                    ks * 8,
                    format!("{:?}", mode).to_lowercase()
                ));
                let dec_path = out_dir.join(format!(
                    "{}_{}_lok197_{}_out{}",
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

    Ok(())
}