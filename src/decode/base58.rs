use anyhow::{anyhow, Result};

pub fn decode(input: &str) -> Result<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(String::new());
    }

    let bytes = bs58::decode(cleaned)
        .into_vec()
        .map_err(|e| anyhow!("Can't decode base58: {e}"))?;

    String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn base58_decode() {
        assert_eq!(decode("Cn8eVZg").unwrap(), "hello");
    }

    #[test]
    fn invalid_base58() {
        let err = decode("0OIl").unwrap_err().to_string();
        assert!(err.contains("Can't decode base58"));
    }

    #[test]
    fn invalid_utf8() {
        let encoded = bs58::encode([0x80]).into_string();
        let err = decode(&encoded).unwrap_err().to_string();
        assert!(err.contains("UTF-8 conversion error"));
    }
}
