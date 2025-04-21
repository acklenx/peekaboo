mod identify;
mod decode;

use crate::identifier::{Identifier, IdentificationResult};
use crate::decoder::{Decoder, DecryptionAttempt};
use crate::config::Config;


#[derive(Default)]
pub struct VigenereIdentifier {
    min_text_len: usize,
}

#[derive(Default)]
pub struct VigenereDecoder {
    min_text_len: usize,
}

impl VigenereIdentifier {
    pub fn new(config: &Config) -> Self {
        VigenereIdentifier {
            min_text_len: config.vigenere_min_id_len,
        }
    }
}

impl VigenereDecoder {
    pub fn new(config: &Config) -> Self {
        VigenereDecoder {
            min_text_len: config.vigenere_min_dec_len,
        }
    }
}


impl Identifier for VigenereIdentifier {
    fn identify(&self, ciphertext: &str) -> Option<IdentificationResult> {
        identify::run_vigenere_identification(ciphertext, self.min_text_len)
    }
}

impl Decoder for VigenereDecoder {
    fn decrypt(&self, ciphertext: &str) -> Vec<DecryptionAttempt> {
        decode::run_vigenere_decryption(ciphertext, self.min_text_len)
    }

    fn name(&self) -> &'static str {
        "Vigenere"
    }
}
