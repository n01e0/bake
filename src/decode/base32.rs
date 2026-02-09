use anyhow::{anyhow, Result};
use data_encoding::{BASE32, BASE32_NOPAD};

pub fn decode(input: &str) -> Result<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();

    if cleaned.is_empty() {
        return Ok(String::new());
    }

    let normalized = cleaned.to_ascii_uppercase();
    let decoded = BASE32
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32_NOPAD.decode(normalized.as_bytes()))
        .map_err(|e| anyhow!("Can't decode base32: {e}"))?;

    String::from_utf8(decoded).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn standard_decoding() {
        assert_eq!(decode("NBSWY3DP").unwrap(), "hello");
    }

    #[test]
    fn no_padding_decoding() {
        assert_eq!(decode("MY").unwrap(), "f");
    }

    #[test]
    fn lowercase_input() {
        assert_eq!(decode("nbswy3dp").unwrap(), "hello");
    }

    #[test]
    fn allows_whitespace() {
        assert_eq!(decode("NB SW\nY3DP").unwrap(), "hello");
    }

    #[test]
    fn invalid_base32() {
        let err = decode("%%%%").unwrap_err().to_string();
        assert!(err.contains("Can't decode base32"));
    }

    #[test]
    fn invalid_utf8() {
        let err = decode("QA======").unwrap_err().to_string();
        assert!(err.contains("UTF-8 conversion error"));
    }
}
