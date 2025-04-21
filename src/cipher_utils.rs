pub fn shift_char(c: char, shift: i8) -> char {
    if !c.is_ascii_alphabetic() {
        return c;
    }

    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
    let c_val = c as u8;

    let shifted_offset = (c_val as i16 - base as i16 + shift as i16).rem_euclid(26);
    let shifted_char_val = base as i16 + shifted_offset;

    shifted_char_val as u8 as char
}

pub fn shift_char_string(s: &str, shift: i8) -> String {
    s.chars().map(|c| shift_char(c, shift)).collect()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_char() {
        assert_eq!(shift_char('A', 3), 'D');
        assert_eq!(shift_char('a', 3), 'd');
        assert_eq!(shift_char('X', 5), 'C');
        assert_eq!(shift_char('z', 1), 'a');
        assert_eq!(shift_char('D', -3), 'A');
        assert_eq!(shift_char('c', -5), 'x');
        assert_eq!(shift_char(' ', 3), ' ');
        assert_eq!(shift_char('!', -1), '!');
        assert_eq!(shift_char('A', 0), 'A');
        assert_eq!(shift_char('A', 26), 'A');
        assert_eq!(shift_char('A', -26), 'A');
    }

    #[test]
    fn test_shift_char_string() {
        assert_eq!(shift_char_string("ABC", 3), "DEF");
        assert_eq!(shift_char_string("Hello World!", 1), "Ifmmp Xpsme!");
        assert_eq!(shift_char_string("XYZ", 1), "YZA");
        assert_eq!(shift_char_string("ABC", -1), "ZAB");
        assert_eq!(shift_char_string("NoChange", 0), "NoChange");
        assert_eq!(shift_char_string("Test 123", 5), "Yjxy 123");
        assert_eq!(shift_char_string("", 5), "");
    }
}