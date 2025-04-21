use crate::identifier::IdentificationResult;
use crate::analysis;

const MIN_KASISKI_SEQ_LEN: usize = 3;
const MAX_KASISKI_KEY_LEN: usize = 20;


pub(super) fn run_vigenere_identification(ciphertext: &str, min_text_len: usize) -> Option<IdentificationResult> {
    let alpha_text = analysis::get_alphabetic_chars(ciphertext);

    if alpha_text.len() < min_text_len {
        return None;
    }

    let ic = match analysis::calculate_ic(&alpha_text) {
        Some(val) => val,
        None => return None,
    };

    if ic > analysis::ENGLISH_IC - 0.005 {
        return None;
    }

    let key_length_estimates = analysis::estimate_key_lengths(
        &alpha_text,
        MIN_KASISKI_SEQ_LEN,
        MAX_KASISKI_KEY_LEN
    );

    let params_string = if key_length_estimates.is_empty() {
        format!("Low IC ({:.4}) suggests Polyalphabetic, Kasiski inconclusive.", ic)
    } else {
        let top_estimates = key_length_estimates
            .iter()
            .take(5)
            .map(|(len, count)| format!("{} ({})", len, count))
            .collect::<Vec<String>>()
            .join(", ");
        format!("Low IC ({:.4}). Likely Key Lengths (Count): [{}]", ic, top_estimates)
    };

    let confidence = ((analysis::ENGLISH_IC - ic) / (analysis::ENGLISH_IC - analysis::RANDOM_IC))
        .max(0.0)
        .min(1.0);

    Some(IdentificationResult {
        cipher_name: "Vigenere".to_string(),
        confidence_score: confidence,
        parameters: Some(params_string),
    })
}
