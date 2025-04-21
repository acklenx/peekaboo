#[derive(Debug, PartialEq, Default)]
pub struct BasicStats {
    pub char_count_total: usize,
    pub char_count_alpha: usize,
    pub char_count_upper: usize,
    pub char_count_lower: usize,
    pub char_count_numeric: usize,
    pub char_count_whitespace: usize,
    pub char_count_punctuation: usize,
    pub char_count_other: usize,
    pub word_count: usize,
    pub min_word_length: usize,
    pub max_word_length: usize,
    pub average_word_length: f64,
    pub uppercase_percent: f64,
    pub lowercase_percent: f64,
}

pub fn calculate_basic_stats(text: &str) -> Option<BasicStats> {
    if text.is_empty() {
        return None;
    }

    let mut stats = BasicStats {
        min_word_length: usize::MAX,
        ..Default::default()
    };

    let mut total_word_length_sum: usize = 0;

    stats.char_count_total = text.chars().count();

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            stats.char_count_alpha += 1;
            if c.is_ascii_uppercase() {
                stats.char_count_upper += 1;

            } else {
                stats.char_count_lower += 1;
            }
        } else if c.is_ascii_digit() {
            stats.char_count_numeric += 1;
        } else if c.is_ascii_whitespace() {
            stats.char_count_whitespace += 1;
        } else if c.is_ascii_punctuation() {
            stats.char_count_punctuation += 1;
        } else {
            stats.char_count_other += 1;
        }
    }

    for word in text.split_whitespace() {

        let word_len = word.chars().count();
        if word_len > 0 {
            stats.word_count += 1;
            total_word_length_sum += word_len;
            if word_len < stats.min_word_length {
                stats.min_word_length = word_len;
            }
            if word_len > stats.max_word_length {
                stats.max_word_length = word_len;
            }
        }
    }

    if stats.word_count == 0 {
        stats.min_word_length = 0;
        stats.average_word_length = 0.0;
    } else {
        stats.average_word_length = total_word_length_sum as f64 / stats.word_count as f64;
    }

    if stats.char_count_alpha == 0 {
        stats.uppercase_percent = 0.0;
        stats.lowercase_percent = 0.0;
    } else {
        stats.uppercase_percent = (stats.char_count_upper as f64 / stats.char_count_alpha as f64) * 100.0;
        stats.lowercase_percent = (stats.char_count_lower as f64 / stats.char_count_alpha as f64) * 100.0;
    }

    Some(stats)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_calculation() {
        let text = "Four score and seven years ago our fathers brought forth on this continent, a new nation.";
        let stats = calculate_basic_stats(text).unwrap();

        assert_eq!(stats.char_count_alpha, 72);
        assert_eq!(stats.char_count_upper, 1);
        assert_eq!(stats.char_count_lower, 71);
        assert_eq!(stats.word_count, 16);
        assert_eq!(stats.min_word_length, 1);
        assert_eq!(stats.max_word_length, 10);
        assert!((stats.average_word_length - (74.0 / 16.0)).abs() < 1e-6);
        assert!((stats.uppercase_percent - (1.0 / 72.0 * 100.0)).abs() < 1e-6);
        assert!((stats.lowercase_percent - (71.0 / 72.0 * 100.0)).abs() < 1e-6);
        assert_eq!(stats.char_count_punctuation, 2);
        assert_eq!(stats.char_count_whitespace, 15);
        assert_eq!(stats.char_count_numeric, 0);
        assert_eq!(stats.char_count_other, 0);
        assert_eq!(stats.char_count_total, 89);
    }

    #[test]
    fn test_stats_empty() {
        assert!(calculate_basic_stats("").is_none());
    }

    #[test]
    fn test_stats_no_words() {
        let text = " \t \n ";
        let stats = calculate_basic_stats(text).unwrap();
        assert_eq!(stats.word_count, 0);
        assert_eq!(stats.min_word_length, 0);
        assert_eq!(stats.max_word_length, 0);
        assert_eq!(stats.average_word_length, 0.0);
        assert_eq!(stats.char_count_alpha, 0);
    }

    #[test]
    fn test_stats_no_alpha() {
        let text = "123 456 !@.";
        let stats = calculate_basic_stats(text).unwrap();
        assert_eq!(stats.word_count, 3);
        assert_eq!(stats.min_word_length, 3);
        assert_eq!(stats.max_word_length, 3);
        assert!((stats.average_word_length - 3.0).abs() < 1e-6);
        assert_eq!(stats.char_count_alpha, 0);
        assert_eq!(stats.uppercase_percent, 0.0);
        assert_eq!(stats.lowercase_percent, 0.0);
        assert_eq!(stats.char_count_numeric, 6);
        assert_eq!(stats.char_count_punctuation, 3);
    }

    #[test]
    fn test_stats_from_user_example() {
        let text = "Four score and seven years ago our fathers brought forth on this continent a new nation conceived in liberty and dedicated to the proposition that all men are created equal Now we are engaged in a great civil war testing whether that nation or any nation so conceived and so dedicated can long endure We are met on a great battlefield of that war We have come to dedicate a portion of that field as a final resting place for those who here gave their lives that that nation might live It is altogether fitting and proper that we should do this But in a larger sense we cannot dedicate we cannot consecrate we cannot hallow this ground The brave men living and dead who struggled here have consecrated it far above our poor power to add or detract The world will little note nor long remember what we say here but it can never forget what they did here It is for us the living rather to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced It is rather for us to be here dedicated to the great task remaining before us that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion that we here highly resolve that these dead shall not have died in vain that this nation under God shall have a new birth of freedom and that government of the people by the people for the people shall not perish from the earth";
        let stats = calculate_basic_stats(text).unwrap();


        let expected_alpha_len = 1149;
        let expected_word_count = 268;
        let expected_min_word_len = 1;


        assert_eq!(stats.char_count_alpha, expected_alpha_len);
        assert_eq!(stats.word_count, expected_word_count);
        assert_eq!(stats.min_word_length, expected_min_word_len);
        assert_eq!(stats.max_word_length, 11);


        let expected_avg = 1149.0 / 268.0;

        assert!((stats.average_word_length - expected_avg).abs() < 0.01, "Average word length mismatch");


        assert_eq!(stats.char_count_upper, 11); // Corrected expected value to 11
        // Corrected percentage calculations based on 11 uppercase chars
        assert!((stats.uppercase_percent - (11.0 / 1149.0 * 100.0)).abs() < 0.01);
        assert!((stats.lowercase_percent - ((1149.0-11.0) / 1149.0 * 100.0)).abs() < 0.01);
    }
}
