use crate::crypto::cipher_traits::SymmetricCipherWithRounds;
use crate::crypto::des::DES;
use crate::crypto::des_key_expansion::DesKeyExpansion;
use crate::crypto::des_transformation::DesTransformation;
use crate::crypto::encryption_transformation::EncryptionTransformation;
use std::cell::RefCell;
use std::sync::Arc;
use std::thread_local;

thread_local! {
    static TL_DES: RefCell<DES> = RefCell::new(
        DES::new(
            Arc::new(DesKeyExpansion),
            Arc::new(DesTransformation),
        )
    );
}

pub struct DesAdapter;

impl DesAdapter {
    pub fn new() -> Self {
        DesAdapter
    }
}

impl EncryptionTransformation for DesAdapter {
    fn transform(&self, data: &[u8], round_key: &[u8]) -> Vec<u8> {
        assert_eq!(round_key.len(), 8, "DES round key must be 8 bytes");
        TL_DES.with(|cell| {
            let mut des = cell.borrow_mut();
            des.set_key_with_rounds(round_key);
            des.encrypt(data)
        })
    }
}
