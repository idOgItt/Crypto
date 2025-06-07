pub fn add(left: u64, right: u64) -> u64 {
    left + right
}
pub mod crypto;
pub use crypto::loki97::Loki97Cipher; // Re-export for convenience
pub use symmetric_cipher::crypto as symmetric_crypto;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
