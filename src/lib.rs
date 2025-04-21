// src/lib.rs

// Declare modules as public so they are accessible
pub mod analysis;
pub mod cipher_utils;
pub mod ciphers;
pub mod config;
pub mod decoder;
pub mod identifier;
pub mod text_stats;

// Re-export items needed by main.rs and tests
pub use config::Config;
pub use decoder::{DecryptionAttempt, Decoder};
pub use identifier::{IdentificationResult, Identifier};
// Add pub use for specific cipher structs if needed directly by main/tests
pub use ciphers::caesar::{CaesarDecoder, CaesarIdentifier};
pub use ciphers::vigenere::{VigenereDecoder, VigenereIdentifier};
// Add pub use for analysis functions needed by tests
// (Alternatively, tests can use peekaboo::analysis::function_name)

