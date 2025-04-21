#[derive(Debug, Clone, PartialEq)]
pub struct DecryptionAttempt {
    pub cipher_name: String,
    pub key: String,
    pub plaintext: String,
    pub score: f64,
}

pub trait Decoder {
    fn decrypt(&self, ciphertext: &str) -> Vec<DecryptionAttempt>;
    fn name(&self) -> &'static str;
}