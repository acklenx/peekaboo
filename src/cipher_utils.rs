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
