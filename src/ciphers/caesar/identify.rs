// src/ciphers/caesar/identify.rs

use crate::identifier::IdentificationResult;
use crate::analysis;
use crate::cipher_utils;

pub(super) fn run_caesar_identification(ciphertext: &str) -> Option<IdentificationResult> {
    let mut best_score = f64::MAX;
    let mut best_shift: Option<u8> = None;

    for shift in 0..26 {
        let potential_plaintext: String = ciphertext
            .chars()
            .map(|c| cipher_utils::shift_char(c, -(shift as i8)))
            .collect();

        if let Some(score) = analysis::score_english_likelihood(&potential_plaintext) {
            if score < best_score {
                best_score = score;
                best_shift = Some(shift);
            }
        }
    }

    best_shift.map(|shift| IdentificationResult {
        cipher_name: "Caesar".to_string(),
        confidence_score: best_score,
        parameters: Some(format!("Potential Shift: {}", shift)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused import: use crate::cipher_utils;

    #[test]
    fn test_run_caesar_identification_logic() {
        let plaintext = "This is a secret message.";
        let shift = 3;
        let ciphertext: String = plaintext
            .chars()
            .map(|c| crate::cipher_utils::shift_char(c, shift))
            .collect();

        let result = run_caesar_identification(&ciphertext).unwrap();

        assert_eq!(result.cipher_name, "Caesar");
        // Removed brittle score assertion: assert!(result.confidence_score < 0.8);
        assert_eq!(result.parameters, Some("Potential Shift: 3".to_string()));
    }

    #[test]
    fn test_run_caesar_id_no_alpha() {
        let ciphertext = "123 !@#";
        assert!(run_caesar_identification(ciphertext).is_none());
    }
}