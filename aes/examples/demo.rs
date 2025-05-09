// examples/demo.rs

use std::fs;
use std::path::Path;
use tokio;

use rand::{RngCore, rngs::StdRng};
use rand::SeedableRng;

use rijndael::gf::arithmetic::{Poly, poly_add, poly_mulmod, poly_powmod, poly_inv};
use rijndael::rijndael::sbox::{sbox, inv_sbox};
use rijndael::rijndael::cipher::Rijndael;
use rijndael::rijndael::key_schedule::expand_key;
use symmetric_cipher::crypto::cipher_context::CipherContext;
use symmetric_cipher::crypto::cipher_traits::{SymmetricCipher, SymmetricCipherWithRounds};
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
    // Two irreducible polynomials to demo
    let polys = [
        (
            "0x11B (AES standard)",
            {
                let bits = [1,1,0,1,1,0,0,0,1];
                bits.iter().copied().map(|b| b!=0).collect()
            },
        ),
        (
            "0x12D (alternative)",
            {
                let bits = [1,0,1,1,0,1,0,0,1];
                bits.iter().copied().map(|b| b!=0).collect()
            },
        ),
    ];

    // Key lengths (bytes) and block lengths (bytes) to demo
    let key_sizes = [16usize, 24, 32];
    let block_sizes = [16usize, 24, 32];

    // Cipher modes and paddings
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
    // 0) Key schedule & single-block AES demo
    // --------------------------------------------------------
    println!("=== Key schedule & single-block AES demo ===");
    for (name, poly) in &polys {
        println!("Polynomial: {}", name);
        let key128 = [
            0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c,
        ];
        let round_keys = expand_key(&key128, poly, 16);
        println!(" Round1 key[0..4]: {:02x?}", &round_keys[1][..4]);
        let block = [
            0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
            0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34,
        ];
        let mut cipher = rijndael::rijndael::cipher::Rijndael::new(poly.clone(), 4);
        // 2) Расширяем ключ
        cipher.set_key(&key128).unwrap();

        // 3) Посмотрим первые 4 байта второго раунда
        let round_keys_bytes = cipher.export_round_keys().unwrap();
        println!(" Round1 key[0..4]: {:02x?}", &round_keys_bytes[16..20]);

        // 4) Шифруем и дешифруем
        let enc_vec = cipher.encrypt_block(&block, &[]);
        let dec_vec = cipher.decrypt_block(&enc_vec, &[]);
        println!(" Encrypted block: {:02x?}", enc_vec);
        assert_eq!(dec_vec, block);
    }

    // --------------------------------------------------------
    // 1) GF(2ⁿ) arithmetic
    // --------------------------------------------------------
    println!("\n=== GF(2ⁿ) arithmetic demo ===");
    let a = vec![true,false,true,true]; // x³+x²+1
    let b = vec![true,true,false];      // x²+x
    for (_name, poly) in &polys {
        println!("Using poly {:?}", poly);
        println!("  {:?} + {:?} = {:?}", a, b, poly_add(&a,&b));
        println!("  {:?} * {:?} mod = {:?}", a, b, poly_mulmod(&a,&b, poly));
        println!("  {:?}^5 mod = {:?}", b, poly_powmod(&b,5, poly));
        println!("  {:?}⁻¹ mod = {:?}", a, poly_inv(&a, poly));
    }

    // --------------------------------------------------------
    // 2) S-box demo
    // --------------------------------------------------------
    println!("\n=== S-box demo ===");
    for (name, poly) in &polys {
        println!("Polynomial: {}", name);
        for &x in &[0x00u8, 0x53, 0x7f] {
            let y = sbox(x, poly);
            let x2 = inv_sbox(y, poly);
            println!("  S(0x{:02x}) = 0x{:02x}, InvS → 0x{:02x}", x, y, x2);
            assert_eq!(x2, x);
        }
    }

    // --------------------------------------------------------
    // 3) Random data encryption: modes, key sizes, block sizes, polynomials
    // --------------------------------------------------------
    println!("\n=== Random data demo ===");
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let data: Vec<u8> = (0..1024).map(|_| rng.next_u32() as u8).collect();

    for (poly_name, poly) in &polys {
        for &blk in &block_sizes {
            for &ks in &key_sizes {
                let key = random_key(ks, &mut rng);
                for &mode in &modes {
                    for &pad in &paddings {
                        let iv = if matches!(mode, CipherMode::ECB | CipherMode::RandomDelta) {
                            None
                        } else {
                            Some(vec![0u8; blk])
                        };
                        let mut ctx = CipherContext::new(
                            Box::new(Rijndael::new(poly.clone(), blk / 4)) as _, // Divide by 4 to convert bytes to words
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
                            "poly={} blk={}b key={}b {}+{} OK",
                            poly_name,
                            blk * 8,
                            ks * 8,
                            format!("{:?}", mode).to_lowercase(),
                            format!("{:?}", pad).to_lowercase()
                        );
                    }
                }
            }
        }
    }

    // --------------------------------------------------------
    // 4) File encryption/decryption demo
    // --------------------------------------------------------
    std::fs::create_dir_all("examples/output")?;
    println!("\n=== File demo ===");
    let files = [
        "../symmetric_cipher/examples/files/sample.txt",
        "../symmetric_cipher/examples/files/image.png",
        "../symmetric_cipher/examples/files/song.mp3",
        "../symmetric_cipher/examples/files/video.mp4",
        "../symmetric_cipher/examples/files/big.bin",
    ];

    for input in &files {
        let data = fs::read(input)?;
        let stem = Path::new(input).file_stem().unwrap().to_string_lossy();
        let ext = Path::new(input)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();

        for (poly_name, poly) in &polys {
            for &blk in &block_sizes {
                for &ks in &key_sizes {
                    let key = random_key(ks, &mut rng);
                    for &mode in &modes {
                        for &pad in &paddings {
                            let iv = if matches!(mode, CipherMode::ECB | CipherMode::RandomDelta) {
                                None
                            } else {
                                Some(vec![0u8; blk])
                            };
                            let mut ctx = CipherContext::new(
                                Box::new(Rijndael::new(poly.clone(), blk / 4)) as _, // Divide by 4 to convert bytes to words
                                mode, pad, iv.clone(), Vec::new()
                            );
                            ctx.set_key(&key).unwrap();

                            let enc_path = format!(
                                "examples/output/{}_{}_{}_{}_aes.bin",
                                stem,
                                poly_name,
                                ks * 8,
                                format!("{:?}", mode).to_lowercase()
                            );
                            let mut out_enc = CipherOutput::File(enc_path.clone());
                            ctx.encrypt(CipherInput::Bytes(data.clone()), &mut out_enc).await.unwrap();

                            let dec_path = format!(
                                "examples/output/{}_{}_{}_{}_aes_out{}",
                                stem,
                                poly_name,
                                ks * 8,
                                format!("{:?}", mode).to_lowercase(),
                                ext
                            );
                            let mut out_dec = CipherOutput::File(dec_path.clone());
                            ctx.decrypt(CipherInput::File(enc_path.clone()), &mut out_dec).await.unwrap();

                            assert_eq!(fs::read(input)?, fs::read(&dec_path)?);
                        }
                    }
                }
            }
        }
        println!("File {} OK", input);
    }

    Ok(())
}
