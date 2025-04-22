use peekaboo::ciphers::caesar::{CaesarIdentifier, CaesarDecoder};
use peekaboo::identifier::Identifier;
use peekaboo::decoder::Decoder;
use peekaboo::config::Config;
use peekaboo::cipher_utils;

#[test]
fn test_caesar_full_cycle() {
    let config = Config::default();
    let identifier = CaesarIdentifier::new(&config);
    let decoder = CaesarDecoder::new(&config);
    let plaintext = "This is a secret message.";
    let shift = 3i8;
    let ciphertext: String = cipher_utils::shift_char_string(plaintext, shift);


    let id_result_opt = identifier.identify(&ciphertext);
    assert!(id_result_opt.is_some());
    let id_result = id_result_opt.unwrap();
    assert_eq!(id_result.cipher_name, "Caesar");

    assert!(id_result.parameters.unwrap_or_default().contains(&shift.to_string()));


    let dec_results = decoder.decrypt(&ciphertext);
    assert!(!dec_results.is_empty());
    let best_result = &dec_results[0];
    assert_eq!(best_result.cipher_name, "Caesar");
    assert_eq!(best_result.key, shift.to_string());
    assert_eq!(best_result.plaintext, plaintext);

}

#[test]
fn test_caesar_no_alpha() {
    let config = Config::default();
    let identifier = CaesarIdentifier::new(&config);
    let decoder = CaesarDecoder::new(&config);
    let ciphertext = "123 !@#";


    assert!(identifier.identify(ciphertext).is_none());


    let results = decoder.decrypt(ciphertext);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].plaintext, ciphertext);
    assert_eq!(results[0].key, "0");
}

#[test]
fn test_caesar_short_text_integration() {
    let config = Config::default();
    let identifier = CaesarIdentifier::new(&config);
    let decoder = CaesarDecoder::new(&config);
    let plaintext = "Short";
    let shift = 15i8;
    let ciphertext = cipher_utils::shift_char_string(plaintext, shift);


    if let Some(id_result) = identifier.identify(&ciphertext) {
        assert_eq!(id_result.cipher_name, "Caesar");
        assert!(id_result.parameters.unwrap_or_default().contains(&shift.to_string()));
    }


    let dec_results = decoder.decrypt(&ciphertext);
    assert!(!dec_results.is_empty());
    let best_result = &dec_results[0];
    assert_eq!(best_result.cipher_name, "Caesar");
    assert_eq!(best_result.key, shift.to_string());
    assert_eq!(best_result.plaintext, plaintext);
}

#[test]
fn test_caesar_typical_text_integration() {
    let config = Config::default();
    let identifier = CaesarIdentifier::new(&config);
    let decoder = CaesarDecoder::new(&config);
    let plaintext = "This is a fairly standard sentence for testing purposes";
    let shift = 8i8;
    let ciphertext = cipher_utils::shift_char_string(plaintext, shift);


    let id_result = identifier.identify(&ciphertext).unwrap();
    assert_eq!(id_result.cipher_name, "Caesar");
    assert_eq!(id_result.parameters, Some(format!("Potential Shift: {}", shift)));
    assert!(id_result.confidence_score < 0.5);


    let results = decoder.decrypt(&ciphertext);
    assert!(!results.is_empty());
    let best_result = &results[0];
    assert_eq!(best_result.cipher_name, "Caesar");
    assert_eq!(best_result.key, shift.to_string());
    assert_eq!(best_result.plaintext, plaintext);
    assert!(best_result.score < 0.5);
}

#[test]
fn test_caesar_hardcoded() {
    let config = Config::default();
    let decoder = CaesarDecoder::new(&config);
    // Hardcoded expected plaintext
    let plaintext = "The quick brown dog jumps over the lazy fox";

    // Test case 1: Shift 3
    // Hardcoded ciphertext verified to be correct for shift 3
    let ciphertext1 = "Wkh txlfn eurzq grj mxpsv ryhu wkh odcb ira";
    let shift1 = 3;
    let results1 = decoder.decrypt(ciphertext1);
    assert!(!results1.is_empty());
    assert_eq!(results1[0].key, shift1.to_string());
    assert_eq!(results1[0].plaintext, plaintext, "Shift 3 failed"); // Direct string compare

    // Test case 2: Shift 10
    // Hardcoded ciphertext verified to be correct for shift 10
    let ciphertext2 = "Dro aesmu lbygx nyq tewzc yfob dro vkji pyh";
    let shift2 = 10;
    let results2 = decoder.decrypt(ciphertext2);
    assert!(!results2.is_empty());
    assert_eq!(results2[0].key, shift2.to_string());
    assert_eq!(results2[0].plaintext, plaintext, "Shift 10 failed"); // Direct string compare

    // Test case 3: Shift -5 (or 21)
    // Hardcoded ciphertext verified to be correct for shift -5
    let ciphertext3 = "Ocz lpdxf wmjri yjb ephkn jqzm ocz gvut ajs";
    let shift3_pos = 21;
    let results3 = decoder.decrypt(ciphertext3);
    assert!(!results3.is_empty());
    assert_eq!(results3[0].key, shift3_pos.to_string());
    assert_eq!(results3[0].plaintext, plaintext, "Shift -5 failed"); // Direct string compare
}
