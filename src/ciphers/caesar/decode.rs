use crate::decoder::DecryptionAttempt;
use crate::analysis;
use crate::cipher_utils;
use std::cmp::Ordering;


pub(super) fn run_caesar_decryption(ciphertext: &str) -> Vec<DecryptionAttempt> {
    let mut attempts = Vec::new();

    for shift in 0..26 {
        let target_shift = shift as i8;
        let potential_plaintext: String = ciphertext
            .chars()
            .map(|c| cipher_utils::shift_char(c, -target_shift))
            .collect();

        if let Some(score) = analysis::score_english_likelihood(&potential_plaintext) {
            attempts.push(DecryptionAttempt {
                cipher_name: "Caesar".to_string(),
                key: shift.to_string(),
                plaintext: potential_plaintext,
                score,
            });
        } else if !potential_plaintext.is_empty() && attempts.is_empty() {
            if shift == 0 && ciphertext.chars().any(|c| !c.is_ascii_alphabetic()) {
                attempts.push(DecryptionAttempt {
                    cipher_name: "Caesar".to_string(),
                    key: shift.to_string(),
                    plaintext: potential_plaintext,
                    score: f64::MAX,
                });
            }
        }
    }

    attempts.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal));

    attempts
}
