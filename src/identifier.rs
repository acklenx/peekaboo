#[derive(Debug, Clone, PartialEq)]
pub struct IdentificationResult {
    pub cipher_name: String,
    pub confidence_score: f64,
    pub parameters: Option<String>,
}

pub trait Identifier {
    fn identify(&self, ciphertext: &str) -> Option<IdentificationResult>;
}