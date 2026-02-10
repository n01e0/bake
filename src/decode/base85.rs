use anyhow::{anyhow, Result};

pub fn decode(input: &str) -> Result<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(String::new());
    }

    let decoded = ascii85::decode(&cleaned).map_err(|e| anyhow!("Can't decode base85: {e}"))?;
    String::from_utf8(decoded).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn base85_decode() {
        assert_eq!(decode("BOu!rDZ").unwrap(), "hello");
    }

    #[test]
    fn invalid_base85() {
        assert!(decode("%%%%").is_err());
    }
}
