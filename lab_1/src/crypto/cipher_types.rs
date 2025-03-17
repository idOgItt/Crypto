#[derive(Debug, Clone, Copy)]
pub enum CipherMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RandomDelta,
}

#[derive(Debug, Clone, Copy)]
pub enum PaddingMode {
    Zeros,
    ANSI_X923,
    PKCS7,
    ISO10126,
}

pub enum CipherInput {
    Bytes(Vec<u8>),
    File(String),
}

pub enum CipherOutput {
    Buffer(Box<Vec<u8>>),
    File(String),
}
