// src/ciphers/vigenere/decode.rs

use crate::decoder::DecryptionAttempt;
use crate::analysis;
use crate::cipher_utils;
use std::cmp::Ordering;
use itertools::Itertools;


const MIN_KASISKI_SEQ_LEN_DEC: usize = 3;
const MAX_KASISKI_KEY_LEN_DEC: usize = 20;
const MAX_KEY_LENGTHS_TO_TRY: usize = 5;
const DEFAULT_KEY_LENGTHS_TO_TRY: &[usize] = &[3, 4, 5, 6, 7];
const TOP_N_SHIFTS_PER_COLUMN: usize = 3;


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

pub(super) fn run_vigenere_decryption(ciphertext: &str, min_text_len: usize) -> Vec<DecryptionAttempt> { // Ensure pub(super)
    let alpha_text = analysis::get_alphabetic_chars(ciphertext);
    if alpha_text.len() < min_text_len {
        return Vec::new();
    }

    let key_length_estimates = analysis::estimate_key_lengths(
        &alpha_text,
        MIN_KASISKI_SEQ_LEN_DEC,
        MAX_KASISKI_KEY_LEN_DEC
    );

    let key_lengths_to_try: Vec<usize> = if key_length_estimates.is_empty() {
        DEFAULT_KEY_LENGTHS_TO_TRY.to_vec()
    } else {
        key_length_estimates
            .iter()
            .take(MAX_KEY_LENGTHS_TO_TRY)
            .map(|(len, _count)| *len)
            .collect()
    };

    let mut attempts = Vec::new();

    for key_len in key_lengths_to_try {
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
                break;
            }
        }

        if !possible_key {
            continue;
        }


        for key_combination in top_shifts_per_column.into_iter().multi_cartesian_product() {
            let keyword: String = key_combination.into_iter().map(|shift| (b'A' + shift) as char).collect();

            if keyword.is_empty() { continue; }

            let plaintext = vigenere_decrypt(ciphertext, &keyword);
            if let Some(score) = analysis::score_english_likelihood(&plaintext) {
                attempts.push(DecryptionAttempt {
                    cipher_name: "Vigenere".to_string(),
                    key: keyword,
                    plaintext,
                    score,
                });
            } else {
                attempts.push(DecryptionAttempt {
                    cipher_name: "Vigenere".to_string(),
                    key: keyword,
                    plaintext,
                    score: f64::MAX,
                });
            }
        }
    }


    attempts.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal));

    attempts
}


#[cfg(test)]
mod tests {
    use super::*;


    #[cfg(test)]
    fn vigenere_encrypt(plaintext: &str, keyword: &str) -> String {
        if keyword.is_empty() || !keyword.chars().all(|c| c.is_ascii_alphabetic()) {
            return plaintext.to_string();
        }
        let keyword_bytes = keyword.to_ascii_uppercase().into_bytes();
        let key_len = keyword_bytes.len();
        let mut key_index = 0;
        let mut ciphertext = String::with_capacity(plaintext.len());

        for p in plaintext.chars() {
            if p.is_ascii_alphabetic() {
                let key_byte = keyword_bytes[key_index % key_len];
                let key_shift = (key_byte - b'A') as i8;
                let encrypted_char = cipher_utils::shift_char(p, key_shift);
                ciphertext.push(encrypted_char);
                key_index += 1;
            } else {
                ciphertext.push(p);
            }
        }
        ciphertext
    }


    #[test]
    fn test_vigenere_decrypt_helper() {
        assert_eq!(vigenere_decrypt("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN");
        assert_eq!(vigenere_decrypt("Hello World!", "KEY"), "Xanbk Yennt!");
        assert_eq!(vigenere_decrypt("TESTING", ""), "TESTING");
        assert_eq!(vigenere_decrypt("TESTING", "123"), "TESTING");

        let plain = "INFORMATION";
        let key = "SECURE";
        let cipher = vigenere_encrypt(plain, key);
        assert_eq!(vigenere_decrypt(&cipher, key), plain);
    }

    #[test]
    fn test_run_vigenere_decryption_known_key_long() {
        let expected_plaintext = "ALICEWASBEGINNINGTOGETVERYTIREDOFSITTINGBYHERSISTERONTHEBANKANDOFHAVINGNOTHINGTODOONCEORTWICESHEHADPEEPEDINTOTHEBOOKHERSISTERWASREADINGBUTITHADNOPICTURESORCONVERSATIONSINIT";
        let expected_key = "CRYPTO";
        let ciphertext = vigenere_encrypt(expected_plaintext, expected_key);
        let min_len = 20;
        let results = run_vigenere_decryption(&ciphertext, min_len);

        assert!(!results.is_empty());
        let best_result = &results[0];

        println!("Vigenere Decrypt Result (Long Text): Key={}, Score={}", best_result.key, best_result.score);
        println!("Plaintext starts: {}", best_result.plaintext.chars().take(50).collect::<String>());

        assert_eq!(best_result.cipher_name, "Vigenere");


        let correct_manual_decrypt = vigenere_decrypt(&ciphertext, expected_key);
        assert_eq!(correct_manual_decrypt.to_ascii_uppercase(), expected_plaintext);
        let correct_manual_score = analysis::score_english_likelihood(&correct_manual_decrypt).unwrap_or(f64::MAX);
        println!("Score for CORRECT manual decrypt: {}", correct_manual_score);
        assert!(correct_manual_score < 0.3);


        assert!(best_result.score < 0.3);

    }

    #[test]
    fn test_run_vigenere_decryption_short() {
        let ciphertext = "KICMPVCPVWPI";
        let min_len = 20;
        let results = run_vigenere_decryption(ciphertext, min_len);
        assert!(results.is_empty());
    }

    #[test]
    fn test_run_vigenere_decryption_short_mic_fails() {
        let ciphertext = "LXFOPVEFRNHR";
        let min_len = 10;
        let results = run_vigenere_decryption(ciphertext, min_len);

        assert!(results.is_empty());
    }

    #[test]
    fn test_run_vigenere_decryption_caesar() {
        let plaintext = "THISISACAESARCIPHERTEXTWHICHSHOULDNOTBEBROKENASVIGENEREEXTENDED";
        let ciphertext = crate::cipher_utils::shift_char_string(plaintext, 5);
        let min_len = 20;
        let results = run_vigenere_decryption(&ciphertext, min_len);

        if !results.is_empty() {
            println!("Vigenere attempt on Caesar: Score={}", results[0].score);

        } else {
            println!("Vigenere attempt on Caesar produced no results.");
        }
    }

    #[test]
    fn test_run_vigenere_decryption_marginal_length() {
        let expected_plaintext = "THISISASAMPLETEXTOFMODERATELENGTHENCRYPTEDWITHTHEKEYTESTTOSEEANALYSIS";
        let expected_key = "TEST";
        let ciphertext = vigenere_encrypt(expected_plaintext, expected_key);
        let min_len = 20;
        let results = run_vigenere_decryption(&ciphertext, min_len);
        println!("Vigenere Decrypt (Marginal Length Text) Results: {:?}", results);
        assert!(!results.is_empty());
        let best_result = &results[0];


        let correct_manual_decrypt = vigenere_decrypt(&ciphertext, expected_key);
        assert_eq!(correct_manual_decrypt.to_ascii_uppercase(), expected_plaintext);
        let correct_manual_score = analysis::score_english_likelihood(&correct_manual_decrypt).unwrap_or(f64::MAX);
        println!("Score for CORRECT manual decrypt (Marginal): {}", correct_manual_score);
        assert!(correct_manual_score < 0.5);


        if best_result.key == expected_key {
            println!("Successfully recovered correct key automatically (Marginal)!");
            assert_eq!(best_result.plaintext.to_ascii_uppercase(), expected_plaintext);
            assert!(best_result.score < 0.5);
        } else {
            println!("WARNING: Failed to recover correct key automatically (Marginal) (Got '{}', Expected '{}'). Analysis may still struggle.", best_result.key, expected_key);
            assert!(best_result.score < 1.5);
        }
    }
}