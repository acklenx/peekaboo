use peekaboo::cipher_utils::*;

#[test]
fn test_shift_char_test() {
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
fn test_shift_char_string_test() {
    assert_eq!(shift_char_string("ABC", 3), "DEF");
    assert_eq!(shift_char_string("Hello World!", 1), "Ifmmp Xpsme!");
    assert_eq!(shift_char_string("XYZ", 1), "YZA");
    assert_eq!(shift_char_string("ABC", -1), "ZAB");
    assert_eq!(shift_char_string("NoChange", 0), "NoChange");
    assert_eq!(shift_char_string("Test 123", 5), "Yjxy 123");
    assert_eq!(shift_char_string("", 5), "");
}
