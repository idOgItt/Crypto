pub trait KeyExpansion {
    fn generate_round_keys(&self, key: &[u8]) -> Vec<Vec<u8>>;
}
