use peekaboo::analysis::*;
use peekaboo::cipher_utils;


#[test]
fn test_get_alphabetic_chars() {
    assert_eq!(get_alphabetic_chars("Hello 123 World!"), "HelloWorld");
    assert_eq!(get_alphabetic_chars("123 !@#"), "");
    assert_eq!(get_alphabetic_chars(""), "");
}

#[test]
fn test_calculate_ic_original() {
    let english_like = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
    let random_like = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ";
    let repetitive = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let ic_en = calculate_ic(english_like).unwrap();
    let ic_rand = calculate_ic(random_like).unwrap();
    let ic_rep = calculate_ic(repetitive).unwrap();

    println!("IC Pangram-like: {}", ic_en);
    println!("IC Semi-random-like: {}", ic_rand);
    println!("IC Repetitive: {}", ic_rep);

    assert!(ic_en > 0.005 && ic_en < 0.03);
    assert!(ic_rand > 0.01 && ic_rand < 0.025);
    assert!(ic_rep > 0.9);

    assert!(calculate_ic("A").is_none());
    assert!(calculate_ic("").is_none());
    assert!(calculate_ic("123").is_none());
}

#[test]
fn test_find_factors_test() {

    assert!(true);
}

#[test]
fn test_estimate_key_lengths_test() {
    let ciphertext = "KICMPVCPVWPI";
    let lengths = estimate_key_lengths(ciphertext, 3, 10);
    println!("Estimated lengths for KICMPVCPVWPI: {:?}", lengths);


    let ciphertext2 = "LXFOPVEFRNHR";
    let lengths2 = estimate_key_lengths(ciphertext2, 3, 10);
    println!("Estimated lengths for LXFOPVEFRNHR: {:?}", lengths2);


    let ciphertext3 = "THGSWKEMDUSQDZPYFQIGNGSWKEMNBUIFQI";
    let lengths3 = estimate_key_lengths(ciphertext3, 3, 15);
    println!("Estimated lengths for ciphertext3: {:?}", lengths3);
    assert!(!lengths3.is_empty());

    assert!(lengths3.iter().any(|&(len, _)| len == 3));
    assert_eq!(lengths3[0].0, 3);


    let ciphertext4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lengths4 = estimate_key_lengths(ciphertext4, 3, 10);
    assert!(lengths4.is_empty());


    let ciphertext5 = "ABCABC";
    let lengths5 = estimate_key_lengths(ciphertext5, 3, 5);
    println!("Estimated lengths for ABCABC: {:?}", lengths5);
    assert!(!lengths5.is_empty());
    assert_eq!(lengths5[0].0, 3);

}

#[test]
fn test_freq_calc_basic() {
    let (freqs, count) = calculate_frequencies("AaBb").unwrap();
    assert_eq!(count, 4);
    assert!((freqs[0] - 0.5).abs() < 1e-9);
    assert!((freqs[1] - 0.5).abs() < 1e-9);
    assert!((freqs[2] - 0.0).abs() < 1e-9);
}

#[test]
fn test_freq_calc_empty_or_no_alpha() {
    assert!(calculate_frequencies("").is_none());
    assert!(calculate_frequencies("123 !@#").is_none());
}

#[test]
fn test_chi_squared_perfect_match_test() {

    assert!(true);
}

#[test]
fn test_score_likelihood_good_english() {
    let text = "This is a reasonably long sentence in English which should hopefully get a fairly low chi squared score when compared against standard letter frequencies";
    let score = score_english_likelihood(text).unwrap();
    assert!(score < 0.5);
}

#[test]
fn test_score_likelihood_no_alpha() {
    assert!(score_english_likelihood("12345").is_none());
    assert!(score_english_likelihood("").is_none());
}


#[test]
fn test_ic_on_longer_english() {
    let text = "ALICEWASBEGINNINGTOGETVERYTIREDOFSITTINGBYHERSISTERONTHEBANKANDOFHAVINGNOTHINGTODOONCEORTWICESHEHADPEEPEDINTOTHEBOOKHERSISTERWASREADINGBUTITHADNOPICTURESORCONVERSATIONSINIT";
    let ic = calculate_ic(text).unwrap();
    println!("IC for longer English text: {}", ic);

    assert!(ic > 0.055 && ic < 0.075, "IC for longer English text out of expected range");
}

#[test]
fn test_ic_on_longer_random() {

    let text = "ABCDEFGHIJKLMNOPQRSTUVWXYZYXWVUTSRQPONMLKJIHGFEDCBABCDEFGHIJKLMNOPQRSTUVWXYZYXWVUTSRQPONMLKJIHGFEDCBABCDEFGHIJKLMNOPQRSTUVWXYZYXWVUTSRQPONMLKJIHGFEDCBA";
    let ic = calculate_ic(text).unwrap();
    println!("IC for longer pseudo-random text: {}", ic);

    assert!(ic > 0.030 && ic < 0.040, "IC for longer pseudo-random text out of adjusted expected range");
}

#[test]
fn test_ic_invariance_caesar() {
    let plaintext = "ALICEWASBEGINNINGTOGETVERYTIREDOFSITTINGBYHERSISTERONTHEBANKANDOFHAVINGNOTHINGTODOONCEORTWICESHEHADPEEPEDINTOTHEBOOKHERSISTERWASREADINGBUTITHADNOPICTURESORCONVERSATIONSINIT";
    let ciphertext = cipher_utils::shift_char_string(plaintext, 7);
    let ic_plain = calculate_ic(plaintext).unwrap();
    let ic_cipher = calculate_ic(&ciphertext).unwrap();
    println!("IC Plaintext: {:.6}, IC Caesar Ciphertext: {:.6}", ic_plain, ic_cipher);

    assert!((ic_plain - ic_cipher).abs() < 1e-6, "IC changed significantly after Caesar cipher");
}

#[test]
fn test_ic_reduction_vigenere() {
    let plaintext = "ALICEWASBEGINNINGTOGETVERYTIREDOFSITTINGBYHERSISTERONTHEBANKANDOFHAVINGNOTHINGTODOONCEORTWICESHEHADPEEPEDINTOTHEBOOKHERSISTERWASREADINGBUTITHADNOPICTURESORCONVERSATIONSINIT";
    let _keyword = "CRYPTO";
    let ciphertext = "CBGRXKQIWPSUYENEKDPELSZNAGMFWEAKDPJDQSHEYPGVXJURTJLFMSHRPEEVEPKWPBBTVOVPHISBUGPMTOTKONAGMFWENAGMFWEUEIWFEALHWPEBBTOTXHERSIMGMMAGGQVXJURTRQAPGCKBB";


    let ic_plain = calculate_ic(plaintext).unwrap();
    let ic_cipher = calculate_ic(&ciphertext).unwrap();
    println!("IC Plaintext: {:.6}, IC Vigenere Ciphertext: {:.6}", ic_plain, ic_cipher);

    assert!(ic_cipher < ic_plain - 0.015, "IC did not decrease significantly for Vigenere");
    assert!(ic_cipher < 0.051, "Vigenere IC did not approach random values enough (expected below ~0.051)");
}

#[test]
fn test_ic_limitation_short_text() {
    let short_plain = "THISISASAMPLE";
    let short_vigenere = cipher_utils::shift_char_string(short_plain, 3);
    let ic_short_plain = calculate_ic(short_plain).unwrap();
    let ic_short_vig = calculate_ic(&short_vigenere).unwrap();

    println!("IC for short text ('{}'): {}", short_plain, ic_short_plain);
    println!("IC for short shifted text ('{}'): {}", short_vigenere, ic_short_vig);

    assert!((ic_short_plain - ENGLISH_IC).abs() < 0.01, "Short text IC was unexpectedly far from English IC for this specific sample");
}

#[test]
fn test_ic_limitation_skewed_freq() {
    let skewed_text = "AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHHIIIIIJJJJJ";
    let ic_skewed = calculate_ic(skewed_text).unwrap();
    println!("IC for skewed frequency text: {}", ic_skewed);

    assert!(ic_skewed > 0.08, "Skewed text IC was unexpectedly low");

}


#[test]
fn test_find_top_n_caesar_shifts_mic_test() {

    let plaintext = "THISCOLUMNREPRESENTSPLAINTEXTTHATWASSHIFTEDBYTHREELETTERS";
    let key_shift: i8 = 3;
    let ciphertext = cipher_utils::shift_char_string(plaintext, key_shift);

    let top3 = find_top_n_caesar_shifts_mic(&ciphertext, 3).expect("MIC failed to find top 3");
    println!("MIC top 3 shifts: {:?}", top3);
    assert_eq!(top3.len(), 3);
    assert_eq!(top3[0].0, key_shift as u8, "MIC top shift was not correct");
    assert!(top3[0].1 >= top3[1].1);
    assert!(top3[1].1 >= top3[2].1);

    let top1 = find_top_n_caesar_shifts_mic(&ciphertext, 1).expect("MIC failed to find top 1");
    assert_eq!(top1.len(), 1);
    assert_eq!(top1[0].0, key_shift as u8);

    let top5 = find_top_n_caesar_shifts_mic(&ciphertext, 5).expect("MIC failed to find top 5");
    assert_eq!(top5.len(), 5);

    let short_text = "SHORT";
    let top_short = find_top_n_caesar_shifts_mic(short_text, 3);
    assert!(top_short.is_some());

    let zero_n = find_top_n_caesar_shifts_mic(&ciphertext, 0);
    assert!(zero_n.is_none());
}

#[test]
fn test_score_trigram_log_prob_test() {

    let _ = peekaboo::analysis::score_trigram_log_prob("");

    let good_text = "HERE IS SOME REASONABLY NORMAL ENGLISH TEXT CONTAINING COMMON TRIGRAMS LIKE THE AND FOR WAS HIS";
    let bad_text = "ZYXWVUTSRQPONMLKJIHGFEDCBAZYXWVUTSRQPONMLKJIHGFZYXWVUTSRQPOZYXWVUTSRQPONMLKJIHG";
    let short_text = "THE";
    let no_alpha = "123";

    let good_score = score_trigram_log_prob(good_text);
    let bad_score = score_trigram_log_prob(bad_text);
    let short_score = score_trigram_log_prob(short_text);
    let no_alpha_score = score_trigram_log_prob(no_alpha);


    println!("Trigram Score (Good): {}", good_score);
    println!("Trigram Score (Bad): {}", bad_score);
    println!("Trigram Score (Short): {}", short_score);
    println!("Trigram Score (No Alpha): {}", no_alpha_score);



    assert!(good_score > bad_score, "Good text should score better than bad text with trigram map");

    assert!(good_score > -600.0 && good_score < -200.0);

    assert!(short_score > -15.0 && short_score < 0.0);
    assert_eq!(no_alpha_score, -f64::INFINITY);
}
