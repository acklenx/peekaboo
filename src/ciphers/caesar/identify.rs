use crate::identifier::IdentificationResult;
use crate::analysis; // Added use statement
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
