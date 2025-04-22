use crate::decoder::DecryptionAttempt;
use crate::analysis;
use crate::cipher_utils;
use std::cmp::Ordering;
use itertools::Itertools;


const MIN_KASISKI_SEQ_LEN_DEC: usize = 3;
const MAX_KASISKI_KEY_LEN_DEC: usize = 12; // Reduced from 20 to limit estimator search space
const MAX_KEY_LENGTHS_TO_TRY: usize = 4;
const DEFAULT_KEY_LENGTHS_TO_TRY: &[usize] = &[2, 3, 4, 5, 6, 7];
const TOP_N_SHIFTS_PER_COLUMN: usize = 3;
const MAX_VIGENERE_KEY_LEN_TO_ATTEMPT: usize = 15; // Keep this filter too, though redundant if above is lower
const PROGRESS_UPDATE_INTERVAL: usize = 10000;


fn vigenere_decrypt(ciphertext: &str, keyword: &str) -> String {
    if keyword.is_empty() || !keyword.chars().all(|c| c.is_ascii_alphabetic()) {
        return ciphertext.to_string();
    }
    let keyword_bytes = keyword.to_ascii_uppercase().into_bytes();
    let key_len = keyword_bytes.len();
    let mut key_index = 0;
    let mut plaintext = String::with_capacity(ciphertext.len());

    for c in ciphertext.chars() {
        if c.is_ascii_alphabetic() {
            let key_byte = keyword_bytes[key_index % key_len];
            let key_shift = (key_byte - b'A') as i8;
            let decrypted_char = cipher_utils::shift_char(c, -key_shift);
            plaintext.push(decrypted_char);
            key_index += 1;
        } else {
            plaintext.push(c);
        }
    }
    plaintext
}


pub(super) fn run_vigenere_decryption(ciphertext: &str, min_text_len: usize) -> Vec<DecryptionAttempt> {

    let alpha_text = analysis::get_alphabetic_chars(ciphertext);
    if alpha_text.len() < min_text_len {

        return Vec::new();
    }


    let icp_estimates = analysis::estimate_key_length_ic_periodicity(
        &alpha_text,
        2,
        MAX_KASISKI_KEY_LEN_DEC
    );

    let key_lengths_to_try: Vec<usize> = if !icp_estimates.is_empty() {
        println!("INFO: Using key lengths from IC Periodicity Test.");
        icp_estimates
            .iter()
            .take(MAX_KEY_LENGTHS_TO_TRY)
            .map(|(len, _score)| *len)
            .collect()
    } else {

        let kasiski_estimates = analysis::estimate_key_lengths(
            &alpha_text,
            MIN_KASISKI_SEQ_LEN_DEC,
            MAX_KASISKI_KEY_LEN_DEC
        );
        if !kasiski_estimates.is_empty() {
            println!("INFO: Using key lengths from Kasiski Examination.");
            kasiski_estimates
                .iter()
                .take(MAX_KEY_LENGTHS_TO_TRY)
                .map(|(len, _count)| *len)
                .collect()
        } else {

            println!("INFO: Key length estimation inconclusive, using defaults.");
            DEFAULT_KEY_LENGTHS_TO_TRY.to_vec()
        }
    }
        .into_iter()
        .filter(|&len| len <= MAX_VIGENERE_KEY_LEN_TO_ATTEMPT)
        .collect();

    println!("INFO: Final key lengths to attempt: {:?}", key_lengths_to_try);


    let mut attempts = Vec::new();

    for key_len in &key_lengths_to_try {
        let key_len = *key_len;
        if key_len == 0 { continue; }


        let mut top_shifts_per_column: Vec<Vec<u8>> = Vec::with_capacity(key_len);
        let mut possible_key = true;

        for i in 0..key_len {
            let column: String = alpha_text
                .chars()
                .skip(i)
                .step_by(key_len)
                .collect();



            if let Some(top_shifts) = analysis::find_top_n_caesar_shifts_mic(&column, TOP_N_SHIFTS_PER_COLUMN) {
                top_shifts_per_column.push(top_shifts.into_iter().map(|(shift, _score)| shift).collect());
            } else {

                possible_key = false;
                println!("INFO: Vigenere analysis for key length {} skipped: Column {} too short for MIC analysis.", key_len, i);
                break;
            }
        }

        if !possible_key {

            continue;
        }


        let total_combinations: usize = top_shifts_per_column.iter().map(|v| v.len()).product();


        if total_combinations > PROGRESS_UPDATE_INTERVAL * 2 {
            println!("INFO: Vigenere trying key length {}: Testing {} possible keywords...", key_len, total_combinations);
        } else {
            println!("INFO: Vigenere trying key length {}: Testing {} possible keywords...", key_len, total_combinations);
        }


        let combinations_iter = top_shifts_per_column.clone().into_iter().multi_cartesian_product();
        let mut _combinations_processed: usize = 0;


        for key_combination in combinations_iter {
            _combinations_processed += 1;


            if total_combinations > PROGRESS_UPDATE_INTERVAL && _combinations_processed % PROGRESS_UPDATE_INTERVAL == 0 {
                println!("INFO: ... checked {} / {} combinations for length {}", _combinations_processed, total_combinations, key_len);
            }


            let keyword: String = key_combination.into_iter().map(|shift| (b'A' + shift) as char).collect();

            if keyword.is_empty() { continue; }

            let plaintext = vigenere_decrypt(ciphertext, &keyword);

            let score = analysis::score_trigram_log_prob(&plaintext);



            attempts.push(DecryptionAttempt {
                cipher_name: "Vigenere".to_string(),
                key: keyword,
                plaintext,
                score,
            });
        }

        println!("INFO: Finished testing key length {}.", key_len);
    }



    attempts.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));

    attempts
}
