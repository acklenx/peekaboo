use std::io::{self, Write};
use std::process;

mod analysis;
mod cipher_utils;
mod identifier;
mod decoder;
mod ciphers;
mod config;

use crate::identifier::{Identifier, IdentificationResult};
use crate::decoder::Decoder; // Removed DecryptionAttempt from here
use crate::ciphers::caesar::{CaesarIdentifier, CaesarDecoder};
use crate::ciphers::vigenere::{VigenereIdentifier, VigenereDecoder};
use crate::config::Config;

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

fn run_analysis_pass(config: &Config, ciphertext: &str, first_run: bool) -> (bool, bool) {
    let ciphertext_len = ciphertext.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let mut found_identification = false;
    let mut found_any_decryption = false;

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
    let mut identification_results: Vec<IdentificationResult> = Vec::new();

    for id_tool in &available_identifiers {
        if let Some(result) = id_tool.identify(ciphertext) {
            found_identification = true;
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
        }
    }

    if available_identifiers.len() > identification_results.len() {
        println!("  (Note: Some identifiers might have skipped analysis due to text length below configured minimums).");
    }


    if !found_identification {
        println!("Could not identify a likely cipher type based on available identifiers.");
        if first_run {
            println!("Statistical analysis might require longer ciphertext or adjusted settings.");
        }
    } else {
        let best_guess = identification_results.iter().min_by(|a, b| {
            let score_a = if a.cipher_name == "Caesar" { a.confidence_score } else { 1.0 - a.confidence_score };
            let score_b = if b.cipher_name == "Caesar" { b.confidence_score } else { 1.0 - b.confidence_score };
            score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
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
            continue;
        }


        let decryption_attempts = decoder.decrypt(ciphertext);

        if decryption_attempts.is_empty() {
            println!("No successful decryption found for {}.", decoder_name);
            if decoder_name == "Vigenere" {
                println!("Common reasons include: Incorrect key length determined by Kasiski analysis,");
                println!("or insufficient text in columns for reliable frequency analysis.");
            }
        } else {
            found_any_decryption = true;
            println!("Top {} Decryption Results (Lower score is better):", decoder_name);
            for attempt in decryption_attempts.iter().take(5) {
                let plaintext_preview = attempt.plaintext.chars().take(70).collect::<String>();
                let ellipsis = if attempt.plaintext.chars().count() > 70 { "..." } else { "" };
                let key_preview = attempt.key.chars().take(10).collect::<String>()
                    + if attempt.key.chars().count() > 10 { "..." } else { "" };

                println!(
                    "  Key: {:<10} | Score: {:<8.4} | Plaintext: \"{}{}\"",
                    key_preview,
                    attempt.score,
                    plaintext_preview,
                    ellipsis
                );
            }
            if decryption_attempts.len() > 5 {
                println!("  ... (more results available for {})", decoder_name);
            }
        }
    }
    if !found_any_decryption {
        println!("\nNo usable decryptions found by any available decoder during this pass.");
        if first_run {
            println!("Consider providing longer ciphertext.");
        }
    }

    (found_identification, found_any_decryption)
}


fn main() {
    println!("--- Crypto Decoder Tool ---");
    println!("Current Date: April 20, 2025");

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


    let mut config = Config::default();
    let mut first_run = true;

    loop {
        let pass_name = if first_run { "Defaults" } else { "Custom Settings" };
        println!("\n--- Running Analysis Pass ({}) ---", pass_name);

        let (identified, decrypted) = run_analysis_pass(&config, &ciphertext, first_run);

        if identified || decrypted {

            if !first_run || (identified || decrypted) {
                println!("\nAnalysis pass complete. Found potential results.");
            }

            if first_run && !(identified || decrypted) {

            } else {
                break;
            }
        }


        if first_run {
            println!("\n--- Initial analysis with default settings failed ---");
            println!("No likely cipher type identified and no decryptions succeeded.");
            println!("This often happens with short ciphertexts or unusual ciphers.");
            print!("Would you like to try again with custom analysis settings (e.g., lower minimum lengths)? (y/N): ");
            io::stdout().flush().unwrap();
            let mut choice = String::new();
            if io::stdin().read_line(&mut choice).is_err() {
                println!("Error reading input. Exiting.");
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
                break;
            }
        } else {
            println!("\nAnalysis with custom settings also failed to produce results.");
            break;
        }

    }


    println!("\n--- Analysis Complete ---");
}