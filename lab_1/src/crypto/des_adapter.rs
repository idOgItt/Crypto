use crate::crypto::des::DES;
use crate::crypto::encryption_transformation::EncryptionTransformation;

pub struct DesAdapter {
    des: DES,
}

impl DesAdapter {
    pub fn new(des: DES) -> Self {todo!()}
}
impl EncryptionTransformation for DesAdapter {
    fn transform(&self, _: &[u8], _: &[u8]) -> Vec<u8> { todo!() }
}