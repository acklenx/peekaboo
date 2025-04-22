use crate::identifier::IdentificationResult;
use crate::analysis;

const MIN_KASISKI_SEQ_LEN: usize = 3;
const MAX_KASISKI_KEY_LEN: usize = 20;
const VIGENERE_IC_UPPER_THRESHOLD: f64 = 0.060;


pub(super) fn run_vigenere_identification(ciphertext: &str, min_text_len: usize) -> Option<IdentificationResult> {
    let alpha_text = analysis::get_alphabetic_chars(ciphertext);

    if alpha_text.len() < min_text_len {
        return None;
    }

    let ic = match analysis::calculate_ic(&alpha_text) {
        Some(val) => val,
        None => return None,
    };


    if ic > VIGENERE_IC_UPPER_THRESHOLD {
        return None;
    }


    let kasiski_estimates = analysis::estimate_key_lengths(
        &alpha_text,
        MIN_KASISKI_SEQ_LEN,
        MAX_KASISKI_KEY_LEN
    );
    let ic_periodicity_estimates = analysis::estimate_key_length_ic_periodicity(
        &alpha_text,
        2,
        MAX_KASISKI_KEY_LEN
    );

    let mut params_parts = Vec::new();
    params_parts.push(format!("Low IC ({:.4})", ic));

    if !kasiski_estimates.is_empty() {
        let top_kasiski = kasiski_estimates
            .iter()
            .take(3)
            .map(|(len, count)| format!("{} ({})", len, count))
            .collect::<Vec<String>>()
            .join(", ");
        params_parts.push(format!("Kasiski Top: [{}]", top_kasiski));
    } else {
        params_parts.push("Kasiski inconclusive".to_string());
    }

    if !ic_periodicity_estimates.is_empty() {
        let top_icp = ic_periodicity_estimates
            .iter()
            .take(3)
            .map(|(len, avg_ic)| format!("{} ({:.4})", len, avg_ic))
            .collect::<Vec<String>>()
            .join(", ");
        params_parts.push(format!("IC Periodicity Top (Avg IC): [{}]", top_icp));
    } else {
        params_parts.push("IC Periodicity inconclusive".to_string());
    }

    let params_string = params_parts.join(". ");


    let confidence = ((ic - analysis::RANDOM_IC) / (analysis::ENGLISH_IC - analysis::RANDOM_IC))
        .max(0.0)
        .min(1.0);

    let inverted_confidence = 1.0 - confidence;


    Some(IdentificationResult {
        cipher_name: "Vigenere".to_string(),

        confidence_score: inverted_confidence,
        parameters: Some(params_string),
    })
}
