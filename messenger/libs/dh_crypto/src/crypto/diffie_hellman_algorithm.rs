use crate::crypto::key_exchange_traits::{KeyExchangeAlgorithm, KeyPair};
use num_bigint::{BigUint, ToBigUint};
use num_traits::{One, Zero};
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct DhParameters {
    pub p: BigUint,
    pub g: BigUint,
}

pub struct DiffieHellman {
    params: DhParameters,
}

impl KeyExchangeAlgorithm for DiffieHellman {
    type Parameters = DhParameters;
    type SharedSecret = BigUint;

    fn new(params: Self::Parameters) -> Result<Self, &'static str> {
        if params.p <= 3.to_biguint().unwrap() {
            return Err("Parameter 'p' must be greater than 3. For security, 'p' must be a large prime.");
        }
        if !params.p.bit(0) {
            return Err("Parameter 'p' must be an odd prime for typical Diffie-Hellman groups.");
        }
        if params.g <= BigUint::one() || params.g >= (&params.p - BigUint::one()) {
            return Err("Parameter 'g' must be in the range (1, p-1).");
        }
        Ok(Self { params })
    }

    fn generate_keypair(&self, rng: &mut impl RngCore) -> KeyPair {
        let two = 2.to_biguint().unwrap();
        let p_minus_1 = &self.params.p - BigUint::one();

        let mut private_key: BigUint;
        loop {
            let mut private_key_bytes = vec![0u8; 64];
            rng.fill_bytes(&mut private_key_bytes);
            private_key = BigUint::from_bytes_be(&private_key_bytes);

            if private_key >= two && private_key < p_minus_1 {
                break;
            }
        }

        let public_key = self.params.g.modpow(&private_key, &self.params.p);

        KeyPair {
            private_key,
            public_key,
        }
    }

    fn compute_shared_secret(
        &self,
        own_private_key: &BigUint,
        other_public_key: &BigUint,
    ) -> Result<Self::SharedSecret, &'static str> {
        let two = 2.to_biguint().unwrap();
        let p_minus_1 = &self.params.p - BigUint::one();

        if !(*own_private_key >= two && *own_private_key < p_minus_1) {
            return Err("Own private key is out of the valid range [2, p-2].");
        }

        if *other_public_key < two || *other_public_key >= self.params.p {
            return Err("Other party's public key is out of the valid range [2, p-1].");
        }

        Ok(other_public_key.modpow(own_private_key, &self.params.p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn get_rfc3526_group14_params() -> DhParameters {
        let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
        let g_val: u64 = 2;
        DhParameters {
            p: BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap(),
            g: g_val.to_biguint().unwrap(),
        }
    }

    #[test]
    fn diffie_hellman_key_exchange_success() {
        let params = get_rfc3526_group14_params();
        let dh_context = DiffieHellman::new(params).expect("Failed to create DH context");

        let mut rng_alice = StdRng::seed_from_u64(0xDEADBEEFCAFEA11C);
        let mut rng_bob = StdRng::seed_from_u64(0xBAADBEEFCAFE0B0B);

        let alice_keypair = dh_context.generate_keypair(&mut rng_alice);
        assert!(
            alice_keypair.public_key > BigUint::one()
                && alice_keypair.public_key < dh_context.params.p
        );

        let bob_keypair = dh_context.generate_keypair(&mut rng_bob);
        assert!(
            bob_keypair.public_key > BigUint::one()
                && bob_keypair.public_key < dh_context.params.p
        );

        let secret_alice = dh_context
            .compute_shared_secret(&alice_keypair.private_key, &bob_keypair.public_key)
            .expect("Alice failed to compute shared secret");

        let secret_bob = dh_context
            .compute_shared_secret(&bob_keypair.private_key, &alice_keypair.public_key)
            .expect("Bob failed to compute shared secret");

        assert_eq!(secret_alice, secret_bob);
        assert!(secret_alice > BigUint::one());
    }

    #[test]
    fn test_invalid_parameters_g() {
        let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
        let p_val = BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap();

        let params_g_too_small = DhParameters {
            p: p_val.clone(),
            g: BigUint::one(),
        };
        assert!(DiffieHellman::new(params_g_too_small).is_err());

        let params_g_too_large = DhParameters {
            p: p_val.clone(),
            g: p_val.clone() - BigUint::one(),
        };
        assert!(DiffieHellman::new(params_g_too_large).is_err());
    }

    #[test]
    fn test_invalid_compute_secret_keys() {
        let params = get_rfc3526_group14_params();
        let dh_context = DiffieHellman::new(params).expect("Failed to create DH context");
        let mut rng = StdRng::seed_from_u64(0x12345);
        let keypair = dh_context.generate_keypair(&mut rng);

        let small_priv_key = BigUint::one();
        assert!(dh_context
            .compute_shared_secret(&small_priv_key, &keypair.public_key)
            .is_err());

        let small_pub_key = BigUint::one();
        assert!(dh_context
            .compute_shared_secret(&keypair.private_key, &small_pub_key)
            .is_err());

        let large_pub_key = dh_context.params.p.clone();
        assert!(dh_context
            .compute_shared_secret(&keypair.private_key, &large_pub_key)
            .is_err());
    }
}
