use dh_crypto::{DhParameters, DiffieHellman, KeyExchangeAlgorithm, KeyPair};
use loki97_crypto::Loki97Cipher;
use messenger_protos::EncryptionAlgorithm as ProtoAlgorithm;
use num_bigint::{BigUint, ToBigUint};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use symmetric_cipher::{CipherContext, CipherInput, CipherMode, CipherOutput, PaddingMode, SymmetricCipherWithRounds};
use twofish_crypto::Twofish;

pub struct CryptoState {
    pub dh_keypair_gui: Option<KeyPair>,
    pub shared_secret_key_gui: Option<Vec<u8>>,
}

impl CryptoState {
    pub fn new() -> Self {
        Self {
            dh_keypair_gui: None,
            shared_secret_key_gui: None,
        }
    }

    pub fn reset(&mut self) {
        self.dh_keypair_gui = None;
        self.shared_secret_key_gui = None;
    }
}

pub fn get_standard_dh_params_gui() -> DhParameters {
    let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    let g_val: u64 = 2;
    DhParameters {
        p: BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap(),
        g: g_val.to_biguint().unwrap(),
    }
}

pub fn derive_key_from_shared_secret_gui(secret: &BigUint, key_len_bytes: usize) -> Vec<u8> {
    let secret_bytes = secret.to_bytes_be();
    let mut key = secret_bytes;
    key.resize(key_len_bytes, 0);
    key
}

pub fn generate_dh_keypair() -> Result<KeyPair, String> {
    let dh_params = get_standard_dh_params_gui();
    let dh_context = DiffieHellman::new(dh_params).map_err(|e| format!("Failed to create DH context: {:?}", e))?;
    Ok(dh_context.generate_keypair(&mut OsRng))
}

pub fn compute_shared_secret(private_key: &BigUint, remote_public_key: &[u8], algorithm: ProtoAlgorithm) -> Result<Vec<u8>, String> {
    let dh_params = get_standard_dh_params_gui();
    let dh_context = DiffieHellman::new(dh_params).map_err(|e| format!("Failed to create DH context: {:?}", e))?;

    let remote_pub_key = BigUint::from_bytes_be(remote_public_key);
    let shared_secret = dh_context
        .compute_shared_secret(private_key, &remote_pub_key)
        .map_err(|e| format!("Failed to compute shared secret: {:?}", e))?;

    let key_len = match algorithm {
        ProtoAlgorithm::Loki97 | ProtoAlgorithm::Twofish => 32,
        _ => 32,
    };

    Ok(derive_key_from_shared_secret_gui(&shared_secret, key_len))
}

pub fn create_cipher_box(algorithm: ProtoAlgorithm, key: &[u8]) -> Result<Box<dyn SymmetricCipherWithRounds + Send + Sync>, String> {
    match algorithm {
        ProtoAlgorithm::Loki97 => Ok(Box::new(Loki97Cipher::new(key))),
        ProtoAlgorithm::Twofish => Ok(Box::new(Twofish::new(key))),
        _ => Err("Unsupported encryption algorithm".to_string()),
    }
}

pub async fn encrypt_data(cipher_box: Box<dyn SymmetricCipherWithRounds + Send + Sync>, data: Vec<u8>, iv: Vec<u8>) -> Result<Vec<u8>, String> {
    let initial_additional_params = cipher_box.export_round_keys().unwrap_or_else(|| vec![0u8; 32]);

    let ctx = CipherContext::new(cipher_box, CipherMode::CBC, PaddingMode::PKCS7, Some(iv), initial_additional_params);

    let mut encrypted_output_holder = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.encrypt(CipherInput::Bytes(data), &mut encrypted_output_holder)
        .await
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    match encrypted_output_holder {
        CipherOutput::Buffer(encrypted_data_box) => Ok(encrypted_data_box.to_vec()),
        _ => Err("Unexpected output type".to_string()),
    }
}

pub async fn decrypt_data(cipher_box: Box<dyn SymmetricCipherWithRounds + Send + Sync>, encrypted_data: Vec<u8>, iv: Vec<u8>) -> Result<Vec<u8>, String> {
    let initial_additional_params = cipher_box.export_round_keys().unwrap_or_else(|| vec![0u8; 32]);

    let ctx = CipherContext::new(cipher_box, CipherMode::CBC, PaddingMode::PKCS7, Some(iv), initial_additional_params);

    let mut decrypted_output_holder = CipherOutput::Buffer(Box::new(Vec::new()));
    ctx.decrypt(CipherInput::Bytes(encrypted_data), &mut decrypted_output_holder)
        .await
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    match decrypted_output_holder {
        CipherOutput::Buffer(decrypted_data_box) => Ok(decrypted_data_box.to_vec()),
        _ => Err("Unexpected output type".to_string()),
    }
}

pub fn hash_shared_key(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result = hasher.finalize();
    hex::encode(&result[..4])
}
