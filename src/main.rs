use std::io::{self, Write};
use std::process;

use peekaboo::{
    analysis, // Import the analysis module directly
    config::Config,
    decoder::{DecryptionAttempt, Decoder},
    identifier::{IdentificationResult, Identifier},
    ciphers::{
        caesar::{CaesarDecoder, CaesarIdentifier},
        vigenere::{VigenereDecoder, VigenereIdentifier},
    },
    text_stats,
};


fn read_usize_input(prompt: &str, default: usize) -> usize {
    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("Error reading input. Using default value {}.", default);
            return default;
        }
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() {
            println!("Using default value {}.", default);
            return default;
        }
        match trimmed_input.parse::<usize>() {
            Ok(val) => return val,
            Err(_) => {
                println!("Invalid input. Please enter a whole number (or leave blank for default).");
            }
        }
    }
}

fn run_analysis_pass(
    config: &Config,
    ciphertext: &str,
    first_run: bool
) -> (Vec<IdentificationResult>, Vec<(String, Option<DecryptionAttempt>)>) {
    let ciphertext_len = ciphertext.chars().filter(|c| c.is_ascii_alphabetic()).count();


    let available_identifiers: Vec<Box<dyn Identifier>> = vec![
        Box::new(CaesarIdentifier::new(config)),
        Box::new(VigenereIdentifier::new(config)),
    ];
    let available_decoders: Vec<Box<dyn Decoder>> = vec![
        Box::new(CaesarDecoder::new(config)),
        Box::new(VigenereDecoder::new(config)),
    ];

    println!("\n--- Identifying Cipher ---");
    println!("(Note: Statistical methods effectiveness depends on text length and settings)");

    // --- Raw Ciphertext Analysis ---
    println!("\n--- Raw Ciphertext Analysis ---");
    let ic_option = analysis::calculate_ic(ciphertext);
    let chi2_option = analysis::score_english_likelihood(ciphertext);

    // Report IC
    if let Some(ic) = ic_option {
        println!("  -> Raw Ciphertext Index of Coincidence (IC): {:.4}", ic);
        if ic < (analysis::RANDOM_IC + 0.005) { // Close to random
            println!("     (IC is low, suggests Polyalphabetic Cipher like Vigenere)");
        } else if ic > (analysis::ENGLISH_IC - 0.01) { // Close to English
            println!("     (IC is high, similar to English, suggests Substitution or Transposition)");
        } else {
            println!("     (IC is intermediate)");
        }
    } else {
        println!("  -> Raw Ciphertext Index of Coincidence (IC): Could not calculate");
    }

    // Report Chi-Squared
    if let Some(chi2_score) = chi2_option {
        println!("  -> Raw Ciphertext Chi-Squared Score: {:.4} (vs English)", chi2_score);
        if chi2_score < 3.0 { // Significantly adjusted threshold based on testing
            println!("     (Score < 3.0 suggests frequencies are close to English - possible Transposition Cipher)");
        } else {
            println!("     (Score suggests frequencies differ from English - likely Substitution/Polyalphabetic)");
        }
    } else {
        println!("  -> Raw Ciphertext Chi-Squared Score: Could not calculate");
    }

    // Check for Monoalphabetic Substitution Signature
    if let (Some(ic), Some(chi2_score)) = (ic_option, chi2_option) {
        // Thresholds might need tuning
        const MONO_IC_LOWER_THRESHOLD: f64 = 0.058; // Slightly below English
        const MONO_CHI2_LOWER_THRESHOLD: f64 = 5.0; // Reasonably different from English

        if ic > MONO_IC_LOWER_THRESHOLD && chi2_score > MONO_CHI2_LOWER_THRESHOLD {
            println!("  -> Combined Check: High IC + High Chi2 -> **Possible Monoalphabetic Substitution**");
        }
    }
    println!("--- End Raw Analysis ---");
    // --- End Raw Ciphertext Analysis ---


    let mut identification_results: Vec<IdentificationResult> = Vec::new();
    let mut skipped_identifiers = 0;

    for id_tool in &available_identifiers {
        if let Some(result) = id_tool.identify(ciphertext) {

            let score_context = match result.cipher_name.as_str() {
                "Caesar" => "(Lower is better)",
                "Vigenere" => "(Higher is better)",
                _ => "",
            };
            println!(
                "  -> Identifier [{}] suggests: {} Score: {:.4} {} | Params: {}",
                result.cipher_name,
                result.cipher_name,
                result.confidence_score,
                score_context,
                result.parameters.as_deref().unwrap_or("N/A")
            );
            identification_results.push(result);
        } else {
            skipped_identifiers += 1;
        }
    }

    if skipped_identifiers > 0 {
        println!("  (Note: {} identifier(s) might have skipped analysis due to text length below configured minimums).", skipped_identifiers);
    }


    if identification_results.is_empty() {
        println!("Could not identify a likely cipher type based on available identifiers.");
        if first_run {
            println!("Statistical analysis might require longer ciphertext or adjusted settings.");
        }
    } else {

        let best_guess = identification_results.iter().min_by(|a, b| {
            // Use the corrected Vigenere confidence score (higher is better)
            let score_a = match a.cipher_name.as_str() {
                "Caesar" => 1.0 / (1.0 + a.confidence_score.max(0.0)), // Normalize Chi2
                "Vigenere" => a.confidence_score, // Already 0-1, higher is better
                _ => 0.0,
            };
            let score_b = match b.cipher_name.as_str() {
                "Caesar" => 1.0 / (1.0 + b.confidence_score.max(0.0)), // Normalize Chi2
                "Vigenere" => b.confidence_score, // Already 0-1, higher is better
                _ => 0.0,
            };
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal) // Higher normalized score is better
        });

        if let Some(best) = best_guess {
            println!("Tentative best identification guess: {} (Score: {:.4})",
                     best.cipher_name,
                     best.confidence_score
            );
        } else {
            println!("Could not determine best identification guess.");
        }
    }


    println!("\n--- Attempting Decryption ---");

    let mut top_results: Vec<(String, Option<DecryptionAttempt>)> = Vec::with_capacity(available_decoders.len());


    for decoder in &available_decoders {
        let decoder_name = decoder.name();
        println!("\n--- Trying Decoder: {} ---", decoder_name);

        let min_len_required = match decoder_name {
            "Vigenere" => config.vigenere_min_dec_len,
            _ => 0
        };

        if ciphertext_len < min_len_required {
            println!("Skipping {}: Ciphertext alphabetic length ({}) is less than required minimum ({}).",
                     decoder_name, ciphertext_len, min_len_required);
            if first_run {
                println!("If analysis fails, you'll be offered a chance to lower this setting.");
            }
            top_results.push((decoder_name.to_string(), None));
            continue;
        }


        let decryption_attempts = decoder.decrypt(ciphertext);

        if decryption_attempts.is_empty() {
            println!("No successful decryption found for {}.", decoder_name);
            if decoder_name == "Vigenere" {
                println!("Common reasons include: Incorrect key length determined by Kasiski analysis,");
                println!("or columns too short for MIC analysis, or no candidate key produced valid plaintext.");
            }
            top_results.push((decoder_name.to_string(), None));
        } else {

            top_results.push((decoder_name.to_string(), decryption_attempts.first().cloned()));

            let score_desc = if decoder_name == "Vigenere" {
                "(Higher is better - Trigram Score)"
            } else {
                "(Lower is better - Chi^2 Score)"
            };
            println!("Top {} Decryption Results {}:", decoder_name, score_desc);


            for attempt in decryption_attempts.iter().take(10) {
                let plaintext_preview = attempt.plaintext.chars().take(70).collect::<String>();
                let ellipsis = if attempt.plaintext.chars().count() > 70 { "..." } else { "" };
                let key_preview = attempt.key.chars().take(10).collect::<String>()
                    + if attempt.key.chars().count() > 10 { "..." } else { "" };


                let score_str = if decoder_name == "Vigenere" {
                    format!("{:<8.2}", attempt.score)
                } else {
                    format!("{:<8.4}", attempt.score)
                };

                println!(
                    "  Key: {:<10} | Score: {} | Plaintext: \"{}{}\"",
                    key_preview,
                    score_str,
                    plaintext_preview,
                    ellipsis
                );
            }
            if decryption_attempts.len() > 10 {
                println!("  ... (more results available for {})", decoder_name);
            }
        }
    }


    let actually_decrypted = top_results.iter().any(|(_, r)| r.is_some());
    if !actually_decrypted {
        println!("\nNo usable decryptions found by any available decoder during this pass.");
        if first_run {
            println!("Consider providing longer ciphertext.");
        }
    }

    (identification_results, top_results)
}


fn main() {
    println!("--- Crypto Decoder Tool ---");
    println!("Current Date: April 21, 2025");

    print!("\nEnter ciphertext: ");
    io::stdout().flush().unwrap();
    let mut ciphertext = String::new();
    io::stdin().read_line(&mut ciphertext).expect("Failed to read line");
    let ciphertext = ciphertext.trim();

    if ciphertext.is_empty() {
        println!("No ciphertext entered. Exiting.");
        process::exit(1);
    }
    let alpha_len = ciphertext.chars().filter(|c| c.is_ascii_alphabetic()).count();
    println!("\nReceived Ciphertext (Alphabetic Length: {}): \"{}\"", alpha_len, ciphertext);


    println!("\n--- Basic Text Statistics ---");
    if let Some(stats) = text_stats::calculate_basic_stats(ciphertext) {
        println!("Total Characters: {}", stats.char_count_total);
        println!("Alphabetic Characters: {}", stats.char_count_alpha);
        println!("Word Count: {}", stats.word_count);
        if stats.word_count > 0 {
            println!("Min Word Length: {}", stats.min_word_length);
            println!("Max Word Length: {}", stats.max_word_length);
            println!("Average Word Length: {:.2}", stats.average_word_length);
        }
        if stats.char_count_alpha > 0 {
            println!("Uppercase / Lowercase: {:.1}% / {:.1}%", stats.uppercase_percent, stats.lowercase_percent);
        }
        println!("Numeric Chars: {}", stats.char_count_numeric);
        println!("Whitespace Chars: {}", stats.char_count_whitespace);
        println!("Punctuation Chars: {}", stats.char_count_punctuation);
        println!("Other Chars: {}", stats.char_count_other);
    } else {
        println!("Could not calculate statistics for the input text.");
    }



    let mut config = Config::default();
    let mut first_run = true;

    let final_results: (Vec<IdentificationResult>, Vec<(String, Option<DecryptionAttempt>)>);


    loop {
        let pass_name = if first_run { "Defaults" } else { "Custom Settings" };
        println!("\n--- Running Analysis Pass ({}) ---", pass_name);


        let (id_results, top_dec_results) = run_analysis_pass(&config, &ciphertext, first_run);


        let identified = !id_results.is_empty();
        let decrypted = top_dec_results.iter().any(|(_, r)| r.is_some());


        if first_run && !(identified || decrypted) {
            println!("\n--- Initial analysis with default settings failed ---");
            println!("No likely cipher type identified and no decryptions succeeded.");
            println!("This often happens with short ciphertexts or unusual ciphers.");
            print!("Would you like to try again with custom analysis settings (e.g., lower minimum lengths)? (y/N): ");
            io::stdout().flush().unwrap();
            let mut choice = String::new();
            if io::stdin().read_line(&mut choice).is_err() {
                println!("Error reading input. Exiting.");
                final_results = (id_results, top_dec_results);
                break;
            }

            if choice.trim().to_lowercase().starts_with('y') {

                println!("\n--- Custom Configuration ---");
                println!("You can adjust settings affecting analysis.");
                println!("Press Enter at the prompt to accept the default value shown in [brackets].");

                println!("\n[Vigenere Identification Minimum Length]");
                println!(" - What it is: The shortest ciphertext length (alphabetic characters only)");
                println!("   for which the program will attempt Vigenere IDENTIFICATION using");
                println!("   statistical methods (Index of Coincidence, Kasiski Examination).");
                println!(" - Why it matters: These methods need enough data to be reliable.");
                println!("   Analyzing very short texts statistically often gives misleading results.");
                println!(" - Implications: Setting this too low (e.g., below 25-30) may lead");
                println!("   to incorrect identification or errors. Setting it higher requires");
                println!("   longer ciphertexts but gives more reliable identification.");
                config.vigenere_min_id_len = read_usize_input(
                    &format!("Enter minimum length for Vigenere ID [{}]: ", config.vigenere_min_id_len),
                    config.vigenere_min_id_len
                );

                println!("\n[Vigenere Decryption Minimum Length]");
                println!(" - What it is: The shortest ciphertext length (alphabetic characters only)");
                println!("   for which the program will attempt Vigenere DECRYPTION by trying");
                println!("   to automatically determine the key length and keyword.");
                println!(" - Why it matters: Finding the key length (Kasiski) and determining");
                println!("   the key letters (column frequency analysis) require sufficient text.");
                println!(" - Implications: Setting this too low (e.g., below 20-25) will likely");
                println!("   fail to find the correct key/plaintext for short texts. If you have");
                println!("   a very short text you want to try anyway (e.g., for testing), you");
                println!("   can lower this, but expect unreliable results.");
                config.vigenere_min_dec_len = read_usize_input(
                    &format!("Enter minimum length for Vigenere Decryption [{}]: ", config.vigenere_min_dec_len),
                    config.vigenere_min_dec_len
                );

                println!("Configuration updated. Re-running analysis...");
                first_run = false;

            } else {
                println!("Exiting without trying custom settings.");
                final_results = (id_results, top_dec_results);
                break;
            }
        } else {

            println!("\nAnalysis pass complete.");
            final_results = (id_results, top_dec_results);
            break;
        }

    }


    let (final_id_results, final_top_dec_results) = final_results;


    // --- Determine and Print Overall Best Guess ---

    const CAESAR_CHI2_PREFERENCE_THRESHOLD: f64 = 3.0;

    let mut best_overall_decoder_index: Option<usize> = None;
    let mut highest_normalized_confidence = -1.0;
    let mut preferred_caesar_index: Option<usize> = None;


    for (index, id_result) in final_id_results.iter().enumerate() {
        if id_result.cipher_name == "Caesar" {
            if final_top_dec_results.get(index).map_or(false, |(_, opt)| opt.is_some()) {
                if id_result.confidence_score < CAESAR_CHI2_PREFERENCE_THRESHOLD {
                    preferred_caesar_index = Some(index);
                    break;
                }
            }
        }
    }

    if preferred_caesar_index.is_some() {
        best_overall_decoder_index = preferred_caesar_index;
    } else {

        for (index, id_result) in final_id_results.iter().enumerate() {
            if final_top_dec_results.get(index).map_or(false, |(_, opt)| opt.is_some()) {
                let normalized_confidence = match id_result.cipher_name.as_str() {
                    "Caesar" => 1.0 / (1.0 + id_result.confidence_score.max(0.0)),
                    "Vigenere" => id_result.confidence_score,
                    _ => 0.0,
                };

                if normalized_confidence > highest_normalized_confidence {
                    highest_normalized_confidence = normalized_confidence;
                    best_overall_decoder_index = Some(index);
                }
            }
        }
    }


    println!("\n--- Overall Best Guess ---");
    if let Some(index) = best_overall_decoder_index {

        if let Some(best_attempt) = &final_top_dec_results[index].1 {
            let decoder_name = &best_attempt.cipher_name;
            let score_desc = if decoder_name == "Vigenere" {
                "(Higher is better - Trigram Score)"
            } else {
                "(Lower is better - Chi^2 Score)"
            };
            let score_str = if decoder_name == "Vigenere" {
                format!("{:<8.2}", best_attempt.score)
            } else {
                format!("{:<8.4}", best_attempt.score)
            };
            let key_preview = best_attempt.key.chars().take(10).collect::<String>()
                + if best_attempt.key.chars().count() > 10 { "..." } else { "" };


            println!("Based on identification confidence, the most likely result is:");
            println!("Cipher: {}", decoder_name);
            println!("Score: {} {}", score_str, score_desc);
            println!("Key: {}", key_preview);

            println!("Plaintext:");
            println!("{}", best_attempt.plaintext);
        } else {

            println!("Internal Error: No decryption result found for the best identified cipher index.");
        }

    } else {
        println!("Could not determine a single best guess based on combined identification and successful decryption.");
        println!("Review the results from individual decoders above (if any).");
        println!("Consider providing longer ciphertext or adjusting configuration.");
    }


    println!("\n--- Analysis Complete ---");
}
