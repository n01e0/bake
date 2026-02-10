pub fn encode(input: &[u8], delimiter: &str, prefix: &str) -> String {
    input
        .iter()
        .map(|byte| format!("{prefix}{byte:08b}"))
        .collect::<Vec<_>>()
        .join(delimiter)
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn plain_binary() {
        assert_eq!(encode(b"AB", "", ""), "0100000101000010");
    }

    #[test]
    fn with_delimiter_and_prefix() {
        assert_eq!(encode(b"AB", " ", "0b"), "0b01000001 0b01000010");
    }

    #[test]
    fn utf8_multibyte_bytes() {
        assert_eq!(encode("あ".as_bytes(), "", ""), "111000111000000110000010");
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b"", " ", "0b"), "");
    }
}
