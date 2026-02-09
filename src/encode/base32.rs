use data_encoding::{BASE32, BASE32_NOPAD};

pub fn encode(input: &[u8], no_padding: bool, lower: bool) -> String {
    let encoded = if no_padding {
        BASE32_NOPAD.encode(input)
    } else {
        BASE32.encode(input)
    };

    if lower {
        encoded.to_ascii_lowercase()
    } else {
        encoded
    }
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn standard_encoding() {
        assert_eq!(encode(b"hello", false, false), "NBSWY3DP");
    }

    #[test]
    fn no_padding_encoding() {
        assert_eq!(encode(b"f", true, false), "MY");
    }

    #[test]
    fn lowercase_encoding() {
        assert_eq!(encode(b"hello", false, true), "nbswy3dp");
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b"", false, false), "");
    }
}
