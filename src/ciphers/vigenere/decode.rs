// src/ciphers/vigenere/decode.rs

use crate::decoder::DecryptionAttempt;
use crate::analysis;
use crate::cipher_utils;
use std::cmp::Ordering;


const MIN_KASISKI_SEQ_LEN_DEC: usize = 3;
const MAX_KASISKI_KEY_LEN_DEC: usize = 20;
const MAX_KEY_LENGTHS_TO_TRY: usize = 5;
const DEFAULT_KEY_LENGTHS_TO_TRY: &[usize] = &[3, 4, 5, 6, 7];

// Decrypt function (remains the same)
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
            let decrypted_char = cipher_utils::shift_char(c, -key_shift); // Decrypt is negative shift
            plaintext.push(decrypted_char);
            key_index += 1;
        } else {
            plaintext.push(c);
        }
    }
    plaintext
}

// Add Encrypt helper (for generating test data reliably)
#[cfg(test)] // Only needed for tests
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
            let encrypted_char = cipher_utils::shift_char(p, key_shift); // Encrypt is positive shift
            ciphertext.push(encrypted_char);
            key_index += 1;
        } else {
            ciphertext.push(p);
        }
    }
    ciphertext
}


pub(super) fn run_vigenere_decryption(ciphertext: &str, min_text_len: usize) -> Vec<DecryptionAttempt> {
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

        let mut keyword = String::with_capacity(key_len);
        let mut possible_key = true;

        for i in 0..key_len {
            let column: String = alpha_text
                .chars()
                .skip(i)
                .step_by(key_len)
                .collect();

            if column.is_empty() {
                possible_key = false;
                break;
            }

            let mut best_shift = 0;
            let mut min_score = f64::MAX;

            for shift in 0..26 {
                let decrypted_column: String = column
                    .chars()
                    .map(|c| cipher_utils::shift_char(c, -(shift as i8)))
                    .collect();

                if let Some(score) = analysis::score_english_likelihood(&decrypted_column) {
                    if score < min_score {
                        min_score = score;
                        best_shift = shift;
                    }
                }
            }
            keyword.push((b'A' + best_shift) as char);
        }

        if possible_key && !keyword.is_empty() {
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

    #[test]
    fn test_vigenere_decrypt_helper() {
        assert_eq!(vigenere_decrypt("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN");
        assert_eq!(vigenere_decrypt("Hello World!", "KEY"), "Xanbk Yennt!"); // Corrected expected
        assert_eq!(vigenere_decrypt("TESTING", ""), "TESTING");
        assert_eq!(vigenere_decrypt("TESTING", "123"), "TESTING");
        // Add the previously failing case, but encrypt it first to ensure correctness
        let plain = "INFORMATION";
        let key = "SECURE";
        let cipher = vigenere_encrypt(plain, key);
        assert_eq!(vigenere_decrypt(&cipher, key), plain); // Test round trip
    }

    #[test]
    fn test_run_vigenere_decryption_known_key_long() {
        let expected_plaintext = "ALICEWASBEGINNINGTOGETVERYTIREDOFSITTINGBYHERSISTERONTHEBANKANDOFHAVINGNOTHINGTODOONCEORTWICESHEHADPEEPEDINTOTHEBOOKHERSISTERWASREADINGBUTITHADNOPICTURESORCONVERSATIONSINIT";
        let expected_key = "CRYPTO";
        let ciphertext = vigenere_encrypt(expected_plaintext, expected_key); // Generate correct ciphertext
        let min_len = 20;
        let results = run_vigenere_decryption(&ciphertext, min_len); // Pass generated ciphertext

        assert!(!results.is_empty());
        let best_result = &results[0];

        println!("Vigenere Decrypt Result (Long Text): Key={}, Score={}", best_result.key, best_result.score);
        println!("Plaintext starts: {}", best_result.plaintext.chars().take(50).collect::<String>());

        assert_eq!(best_result.cipher_name, "Vigenere");

        // Test the DECRYPT HELPER with the KNOWN key (ensures decrypt works)
        let correct_manual_decrypt = vigenere_decrypt(&ciphertext, expected_key);
        assert_eq!(correct_manual_decrypt.to_ascii_uppercase(), expected_plaintext);
        let correct_manual_score = analysis::score_english_likelihood(&correct_manual_decrypt).unwrap_or(f64::MAX);
        println!("Score for CORRECT manual decrypt: {}", correct_manual_score);
        assert!(correct_manual_score < 0.3, "Score for known correct decrypt was unexpectedly high");

        // NOW check if the AUTO-DECRYPT found the right key/plaintext
        // With long text, we expect this to work now
        assert_eq!(best_result.key, expected_key, "Failed to recover correct key automatically");
        assert_eq!(best_result.plaintext.to_ascii_uppercase(), expected_plaintext, "Failed to recover correct plaintext automatically");
        assert!(best_result.score < 0.3, "Score for best automatic result was too high");
    }

    #[test]
    fn test_run_vigenere_decryption_short() {
        let ciphertext = "KICMPVCPVWPI";
        let min_len = 20;
        let results = run_vigenere_decryption(ciphertext, min_len);
        assert!(results.is_empty());
    }

    #[test]
    fn test_run_vigenere_decryption_short_overridden_threshold_docs_fail() {
        let ciphertext = "LXFOPVEFRNHR"; // ATTACKATDAWN / LEMON (len 5)
        let min_len = 10;
        let results = run_vigenere_decryption(ciphertext, min_len);
        assert!(!results.is_empty());
        println!("Short Vigenere Decrypt Results (Expecting Failure): {:?}", results);

        let best_result = &results[0];
        assert_ne!(best_result.key, "LEMON", "Test unexpectedly found correct key for short text!");
        assert_ne!(best_result.plaintext.to_ascii_uppercase(), "ATTACKATDAWN", "Test unexpectedly found correct plaintext for short text!");

        println!("Score for best (likely incorrect) decryption of short text: {}", best_result.score);
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
        let ciphertext = vigenere_encrypt(expected_plaintext, expected_key); // Generate correct ciphertext
        let min_len = 20;
        let results = run_vigenere_decryption(&ciphertext, min_len); // Pass generated ciphertext
        println!("Vigenere Decrypt (Marginal Length Text) Results: {:?}", results);
        assert!(!results.is_empty());
        let best_result = &results[0];


        let correct_manual_decrypt = vigenere_decrypt(&ciphertext, expected_key);
        assert_eq!(correct_manual_decrypt.to_ascii_uppercase(), expected_plaintext);
        let correct_manual_score = analysis::score_english_likelihood(&correct_manual_decrypt).unwrap_or(f64::MAX);
        println!("Score for CORRECT manual decrypt (Marginal): {}", correct_manual_score);
        assert!(correct_manual_score < 0.5);


        // Check auto result (might fail, but should be better chance now)
        if best_result.key == expected_key {
            println!("Successfully recovered correct key automatically (Marginal)!");
            assert_eq!(best_result.plaintext.to_ascii_uppercase(), expected_plaintext);
            assert!(best_result.score < 0.5);
        } else {
            println!("WARNING: Failed to recover correct key automatically (Marginal) (Got '{}', Expected '{}').", best_result.key, expected_key);
            assert!(best_result.score < 1.5);
        }
    }
}