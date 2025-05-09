use crate::crypto::key_expansion::KeyExpansion;

pub struct DealKeyExpansion;

impl KeyExpansion for DealKeyExpansion {
    fn generate_round_keys(&self, key: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(key.len(), 24, "DEAL requires 192-bit key (24 bytes)");

        let k1 = key[0..8].to_vec();
        let k2 = key[8..16].to_vec();
        let k3 = key[16..24].to_vec();

        (0..32)
            .map(|i| match i % 3 {
                0 => k1.clone(),
                1 => k2.clone(),
                _ => k3.clone(),
            })
            .collect()
    }
}


impl Clone for DealKeyExpansion {
    fn clone(&self) -> Self {
        DealKeyExpansion
    }
}

