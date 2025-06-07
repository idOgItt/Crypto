use dh_crypto::crypto::{DhParameters, DiffieHellman, KeyExchangeAlgorithm, KeyPair};
use num_bigint::{BigUint, ToBigUint};
use rand::rngs::{OsRng, StdRng}; // OsRng for "real" randomness, StdRng for demo reproducibility
use rand::SeedableRng;

// Using RFC 3526 Group 14 parameters (2048-bit MODP Group)
fn get_standard_dh_params() -> DhParameters {
    let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    let g_val: u64 = 2;

    DhParameters {
        p: BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("Failed to parse prime p from hex"),
        g: g_val.to_biguint().unwrap(),
    }
}

fn main() -> Result<(), &'static str> {
    println!("=== Diffie-Hellman Key Exchange Demo ===");

    // 0. Setup Diffie-Hellman context with standard parameters
    let dh_params = get_standard_dh_params();
    println!("Using DH Parameters:");
    println!(
        "  Prime p (first 16 bytes): {}...",
        &dh_params.p.to_bytes_be()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!("  Generator g: {}", dh_params.g);

    let dh_context = DiffieHellman::new(dh_params.clone())?;
    println!("Diffie-Hellman context created successfully.\n");

    // For reproducible demo, use a seeded RNG. For actual use, prefer OsRng.
    // let mut rng_alice = OsRng;
    // let mut rng_bob = OsRng;
    let mut rng_alice = StdRng::seed_from_u64(0xAF1CE5EED);
    let mut rng_bob = StdRng::seed_from_u64(0xB0B5EED);

    // 1. Alice generates her key pair
    println!("Alice is generating her key pair...");
    let alice_keypair = dh_context.generate_keypair(&mut rng_alice);
    println!(
        "  Alice's Private Key (first 16 bytes): {}...",
        &alice_keypair.private_key.to_bytes_be()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "  Alice's Public Key (first 16 bytes):  {}...\n",
        &alice_keypair.public_key.to_bytes_be()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // 2. Bob generates his key pair
    println!("Bob is generating his key pair...");
    let bob_keypair = dh_context.generate_keypair(&mut rng_bob);
    println!(
        "  Bob's Private Key (first 16 bytes): {}...",
        &bob_keypair.private_key.to_bytes_be()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "  Bob's Public Key (first 16 bytes):  {}...\n",
        &bob_keypair.public_key.to_bytes_be()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // Parties exchange public keys (alice_keypair.public_key and bob_keypair.public_key)

    // 3. Alice computes the shared secret using her private key and Bob's public key
    println!("Alice is computing the shared secret...");
    let shared_secret_alice =
        dh_context.compute_shared_secret(&alice_keypair.private_key, &bob_keypair.public_key)?;
    println!(
        "  Alice's computed shared secret (first 16 bytes): {}...\n",
        &shared_secret_alice.to_bytes_be()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // 4. Bob computes the shared secret using his private key and Alice's public key
    println!("Bob is computing the shared secret...");
    let shared_secret_bob =
        dh_context.compute_shared_secret(&bob_keypair.private_key, &alice_keypair.public_key)?;
    println!(
        "  Bob's computed shared secret (first 16 bytes): {}...\n",
        &shared_secret_bob.to_bytes_be()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );

    // 5. Verification
    if shared_secret_alice == shared_secret_bob {
        println!("SUCCESS: Shared secrets match!");
        println!(
            "Full Shared Secret (hex): {}",
            shared_secret_alice.to_str_radix(16)
        );
    } else {
        println!("ERROR: Shared secrets DO NOT match!");
        return Err("Shared secret mismatch in demo.");
    }

    // The raw shared secret should typically be passed through a Key Derivation Function (KDF)
    // to derive symmetric keys for encryption, MACing, etc. This step is beyond the scope of DH itself.

    Ok(())
}
