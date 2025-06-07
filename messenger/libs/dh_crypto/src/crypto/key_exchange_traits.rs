use num_bigint::BigUint;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: BigUint,
    pub public_key: BigUint,
}

pub trait KeyExchangeAlgorithm: Sized {
    type Parameters;
    type SharedSecret;

    fn new(params: Self::Parameters) -> Result<Self, &'static str>;
    fn generate_keypair(&self, rng: &mut impl RngCore) -> KeyPair;
    fn compute_shared_secret(
        &self,
        own_private_key: &BigUint,
        other_public_key: &BigUint,
    ) -> Result<Self::SharedSecret, &'static str>;
}