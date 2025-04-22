use std::collections::{HashMap, HashSet};
use std::cmp::Ordering;
use once_cell::sync::Lazy;

const ENGLISH_FREQUENCIES: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];
pub const ENGLISH_IC: f64 = 0.0667;
pub const RANDOM_IC: f64 = 1.0 / 26.0; // Approx 0.03846
const MIN_CHARS_FOR_MIC: usize = 5;
const MIN_COUNT_FOR_LOG: f64 = 0.01;

static ENGLISH_TRIGRAM_DATA: Lazy<(HashMap<String, f64>, f64)> = Lazy::new(|| {
    const TRIGRAM_COUNTS_STR: &str = include_str!("english_trigrams.txt");

    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut total_count: u64 = 0;

    for line in TRIGRAM_COUNTS_STR.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            let ngram = parts[0].to_uppercase();
            if ngram.len() == 3 && ngram.chars().all(|c| c.is_ascii_alphabetic()) {
                if let Ok(count) = parts[1].parse::<u64>() {
                    if count > 0 {
                        counts.insert(ngram, count);
                        total_count = total_count.saturating_add(count);
                    }
                }
            }
        }
    }

    if total_count == 0 {
        panic!("Failed to parse any valid trigram counts from embedded 'english_trigrams.txt'. Ensure file exists in src/ and has valid data.");
    }

    let n_float = total_count as f64;
    let floor_log_prob = (MIN_COUNT_FOR_LOG / n_float).log10();
    let mut log_prob_map = HashMap::with_capacity(17576);

    for c1_val in b'A'..=b'Z' {
        for c2_val in b'A'..=b'Z' {
            for c3_val in b'A'..=b'Z' {
                let c1 = c1_val as char;
                let c2 = c2_val as char;
                let c3 = c3_val as char;
                let trigram = format!("{}{}{}", c1, c2, c3);
                let count = counts.get(&trigram).cloned().unwrap_or(0);
                let effective_count = (count as f64).max(MIN_COUNT_FOR_LOG);
                let log_prob = (effective_count / n_float).log10();
                log_prob_map.insert(trigram, log_prob);
            }
        }
    }

    (log_prob_map, floor_log_prob)
});

pub fn score_trigram_log_prob(text: &str) -> f64 {
    let alpha_text = get_alphabetic_chars(text).to_ascii_uppercase();
    if alpha_text.len() < 3 {
        return -f64::INFINITY;
    }

    let (log_prob_map, floor_log_prob) = &*ENGLISH_TRIGRAM_DATA;

    let mut total_log_prob = 0.0;
    let mut trigram_count = 0;

    for i in 0..(alpha_text.len() - 2) {
        if let Some(trigram) = alpha_text.get(i..i + 3) {
            let log_prob = log_prob_map
                .get(trigram)
                .cloned()
                .unwrap_or(*floor_log_prob);
            total_log_prob += log_prob;
            trigram_count += 1;
        }
    }

    if trigram_count == 0 {
        return -f64::INFINITY;
    }

    total_log_prob
}

pub fn calculate_frequencies(text: &str) -> Option<([f64; 26], usize)> {
    let mut counts = [0usize; 26];
    let mut total_chars = 0usize;

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let index = (c.to_ascii_uppercase() as u8 - b'A') as usize;
            if index < 26 {
                counts[index] += 1;
                total_chars += 1;
            }
        }
    }

    if total_chars == 0 {
        return None;
    }

    let mut frequencies = [0.0f64; 26];
    for i in 0..26 {
        frequencies[i] = counts[i] as f64 / total_chars as f64;
    }

    Some((frequencies, total_chars))
}

pub fn find_top_n_caesar_shifts_mic(column_text: &str, n_top: usize) -> Option<Vec<(u8, f64)>> {
    let mut counts = [0usize; 26];
    let mut text_len = 0usize;

    for c in column_text.chars() {
        if c.is_ascii_alphabetic() {
            let index = (c.to_ascii_uppercase() as u8 - b'A') as usize;
            if index < 26 {
                counts[index] += 1;
                text_len += 1;
            }
        }
    }

    if text_len < MIN_CHARS_FOR_MIC || n_top == 0 {
        return None;
    }

    let observed_freq: [f64; 26] = {
        let mut freqs = [0.0; 26];
        for i in 0..26 {
            freqs[i] = counts[i] as f64 / text_len as f64;
        }
        freqs
    };

    let mut shift_scores = Vec::with_capacity(26);

    for g in 0..26 {
        let mut current_mic_score = 0.0;
        for i in 0..26 {
            let observed_index = (i + g) % 26;
            current_mic_score += ENGLISH_FREQUENCIES[i] * observed_freq[observed_index];
        }
        shift_scores.push((g as u8, current_mic_score));
    }


    shift_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));


    shift_scores.truncate(n_top);

    Some(shift_scores)
}


fn chi_squared_score(observed: &[f64; 26], expected: &[f64; 26]) -> f64 {
    let mut score = 0.0;
    for i in 0..26 {
        if expected[i] == 0.0 {
            if observed[i] != 0.0 {
                return f64::MAX;
            }
            continue;
        }
        let difference = observed[i] - expected[i];
        score += difference * difference / expected[i];
    }
    score
}

pub fn score_english_likelihood(text: &str) -> Option<f64> {
    calculate_frequencies(text)
        .map(|(observed_freq, _)| chi_squared_score(&observed_freq, &ENGLISH_FREQUENCIES))
}

pub fn get_alphabetic_chars(text: &str) -> String {
    text.chars().filter(|c| c.is_ascii_alphabetic()).collect()
}

pub fn calculate_ic(text: &str) -> Option<f64> {
    let alpha_text = get_alphabetic_chars(text);
    let n = alpha_text.len();

    if n < 2 {
        return None;
    }

    let mut counts = [0usize; 26];
    for c in alpha_text.chars() {
        let index = (c.to_ascii_uppercase() as u8 - b'A') as usize;
        if index < 26 {
            counts[index] += 1;
        }
    }

    let mut sum = 0.0;
    for count in counts.iter() {
        sum += (*count as f64) * (*count as f64 - 1.0);
    }

    let ic = sum / (n as f64 * (n as f64 - 1.0));
    Some(ic)
}

fn find_factors(number: usize) -> HashSet<usize> {
    let mut factors = HashSet::new();
    if number == 0 { return factors; }
    let limit = (number as f64).sqrt() as usize;
    for i in 1..=limit {
        if number % i == 0 {
            factors.insert(i);
            factors.insert(number / i);
        }
    }
    factors
}

pub fn estimate_key_lengths(text: &str, min_len: usize, max_len: usize) -> Vec<(usize, usize)> {
    let alpha_text = get_alphabetic_chars(text);
    if alpha_text.len() < min_len * 2 {
        return Vec::new();
    }

    let mut sequences: HashMap<String, Vec<usize>> = HashMap::new();
    for len in (min_len..=std::cmp::min(max_len, alpha_text.len() / 2)).rev() {
        for i in 0..=(alpha_text.len() - len) {
            let seq = &alpha_text[i..(i + len)];
            if let Some(positions) = sequences.get_mut(seq) {
                positions.push(i);
            } else {
                if alpha_text[(i+1)..].contains(seq) {
                    sequences.insert(seq.to_string(), vec![i]);
                }
            }
        }

    }


    let mut factor_counts: HashMap<usize, usize> = HashMap::new();
    for positions in sequences.values() {
        if positions.len() > 1 {
            for i in 0..(positions.len() - 1) {
                for j in (i + 1)..positions.len() {
                    let distance = positions[j] - positions[i];
                    let factors = find_factors(distance);
                    for factor in factors {
                        if factor > 1 && factor <= max_len {
                            *factor_counts.entry(factor).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    let mut sorted_factors: Vec<(usize, usize)> = factor_counts.into_iter().collect();

    sorted_factors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    sorted_factors
}

pub fn estimate_key_length_ic_periodicity(text: &str, min_len: usize, max_len: usize) -> Vec<(usize, f64)> {
    let alpha_text = get_alphabetic_chars(text);
    let n = alpha_text.len();
    let mut results = Vec::new();

    if n < min_len * 2 { // Need enough text
        return results;
    }

    for key_len in min_len..=max_len {
        if key_len == 0 || n < key_len { continue; }

        let mut total_ic_for_len = 0.0;
        let mut valid_columns_count = 0;

        for i in 0..key_len {
            let column: String = alpha_text
                .chars()
                .skip(i)
                .step_by(key_len)
                .collect();

            if let Some(ic) = calculate_ic(&column) {
                total_ic_for_len += ic;
                valid_columns_count += 1;
            }
        }

        if valid_columns_count > 0 {
            let avg_ic = total_ic_for_len / valid_columns_count as f64;
            results.push((key_len, avg_ic));
        }
    }

    // Sort by proximity to English IC (closer is better)
    results.sort_by(|a, b| {
        let diff_a = (a.1 - ENGLISH_IC).abs();
        let diff_b = (b.1 - ENGLISH_IC).abs();
        diff_a.partial_cmp(&diff_b).unwrap_or(Ordering::Equal)
    });

    results
}
