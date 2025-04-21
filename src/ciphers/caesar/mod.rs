mod identify;
mod decode;

use crate::identifier::{Identifier, IdentificationResult};
use crate::decoder::{Decoder, DecryptionAttempt};
use crate::config::Config;

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
