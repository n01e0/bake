pub fn encode(input: &[u8], delimiter: &str, prefix: &str, upper: bool) -> String {
    input
        .iter()
        .map(|byte| {
            if upper {
                format!("{prefix}{byte:02X}")
            } else {
                format!("{prefix}{byte:02x}")
            }
        })
        .collect::<Vec<_>>()
        .join(delimiter)
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn plain_lower_hex() {
        assert_eq!(encode(b"foobar", "", "", false), "666f6f626172");
    }

    #[test]
    fn upper_hex_with_delimiter() {
        assert_eq!(encode(b"foobar", ":", "", true), "66:6F:6F:62:61:72");
    }

    #[test]
    fn prefixed_hex() {
        assert_eq!(encode(b"foo", " ", "0x", false), "0x66 0x6f 0x6f");
    }

    #[test]
    fn utf8_bytes() {
        assert_eq!(encode("あ".as_bytes(), "", "", false), "e38182");
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b"", ":", "0x", true), "");
    }
}
