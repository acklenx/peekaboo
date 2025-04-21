// src/config.rs

pub struct Config {
    pub vigenere_min_id_len: usize,
    pub vigenere_min_dec_len: usize,
    // Add other configurable parameters here later if needed
    // pub kasiski_min_seq_len: usize,
    // pub kasiski_max_key_len: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // Set default values matching the previous constants
            vigenere_min_id_len: 30,
            vigenere_min_dec_len: 20,
            // kasiski_min_seq_len: 3,
            // kasiski_max_key_len: 20,
        }
    }
}