// src/ciphers/caesar/mod.rs

mod identify;
mod decode;

use crate::identifier::{Identifier, IdentificationResult};
use crate::decoder::{Decoder, DecryptionAttempt};
use crate::config::Config; // Use Config if needed later

#[derive(Default)]
pub struct CaesarIdentifier;

#[derive(Default)]
pub struct CaesarDecoder;

impl CaesarIdentifier {
    pub fn new(_config: &Config) -> Self {
        Default::default()
    }
}

impl CaesarDecoder {
    pub fn new(_config: &Config) -> Self {
        Default::default()
    }
}

impl Identifier for CaesarIdentifier {
    fn identify(&self, ciphertext: &str) -> Option<IdentificationResult> {
        identify::run_caesar_identification(ciphertext)
    }
}

impl Decoder for CaesarDecoder {
    fn decrypt(&self, ciphertext: &str) -> Vec<DecryptionAttempt> {
        decode::run_caesar_decryption(ciphertext)
    }

    fn name(&self) -> &'static str {
        "Caesar"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_utils;
    use crate::identifier::Identifier;
    use crate::decoder::Decoder;
    use crate::config::Config;

    #[test]
    fn test_caesar_module_structs() {
        let config = Config::default(); // Need config for `new`
        let identifier = CaesarIdentifier::new(&config);
        let decoder = CaesarDecoder::new(&config);
        let plaintext = "Test message for module structure.";
        let shift = 5;
        let ciphertext: String = plaintext
            .chars()
            .map(|c| cipher_utils::shift_char(c, shift))
            .collect();

        let id_result = identifier.identify(&ciphertext).expect("Identification failed");
        assert_eq!(id_result.cipher_name, "Caesar");

        let dec_results = decoder.decrypt(&ciphertext);
        assert!(!dec_results.is_empty(), "Decryption produced no results");
        assert_eq!(dec_results[0].plaintext, plaintext);

        assert_eq!(decoder.name(), "Caesar");
    }
}