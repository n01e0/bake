use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};

pub fn decode(input: &str, url_safe: bool) -> Result<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();

    if cleaned.is_empty() {
        return Ok(String::new());
    }

    let decoded = if url_safe {
        decode_with_optional_padding(&general_purpose::URL_SAFE, &cleaned)
    } else {
        decode_with_optional_padding(&general_purpose::STANDARD, &cleaned)
    }
    .map_err(|e| anyhow!("Can't decode base64: {e}"))?;

    String::from_utf8(decoded).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

fn decode_with_optional_padding(
    engine: &impl Engine,
    input: &str,
) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    engine.decode(input).or_else(|first_err| {
        let remainder = input.len() % 4;
        if remainder == 0 {
            return Err(first_err);
        }

        let padded = format!("{input}{}", "=".repeat(4 - remainder));
        engine.decode(padded)
    })
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn standard_base64() {
        assert_eq!(decode("aGVsbG8=", false).unwrap(), "hello");
    }

    #[test]
    fn allows_whitespace() {
        assert_eq!(decode("aG V s\n bG 8=", false).unwrap(), "hello");
    }

    #[test]
    fn decodes_without_padding() {
        assert_eq!(decode("aGVsbG8", false).unwrap(), "hello");
    }

    #[test]
    fn url_safe_input() {
        assert_eq!(decode("aGVsbG8td29ybGRf", true).unwrap(), "hello-world_");
    }

    #[test]
    fn invalid_base64() {
        let err = decode("@@@", false).unwrap_err().to_string();
        assert!(err.contains("Can't decode base64"));
    }

    #[test]
    fn invalid_utf8() {
        let err = decode("gA==", false).unwrap_err().to_string();
        assert!(err.contains("UTF-8 conversion error"));
    }
}
