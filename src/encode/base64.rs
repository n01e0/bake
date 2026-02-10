use base64::{engine::general_purpose, Engine};

pub fn encode(input: &[u8], url_safe: bool, no_padding: bool) -> String {
    match (url_safe, no_padding) {
        (false, false) => general_purpose::STANDARD.encode(input),
        (false, true) => general_purpose::STANDARD_NO_PAD.encode(input),
        (true, false) => general_purpose::URL_SAFE.encode(input),
        (true, true) => general_purpose::URL_SAFE_NO_PAD.encode(input),
    }
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn standard_encoding() {
        assert_eq!(encode(b"hello", false, false), "aGVsbG8=");
    }

    #[test]
    fn no_padding_encoding() {
        assert_eq!(encode(b"f", false, true), "Zg");
    }

    #[test]
    fn url_safe_encoding() {
        assert_eq!(encode(&[0xfb, 0xff], true, false), "-_8=");
    }

    #[test]
    fn url_safe_no_padding_encoding() {
        assert_eq!(encode(&[0xfb, 0xff], true, true), "-_8");
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b"", false, false), "");
    }
}
