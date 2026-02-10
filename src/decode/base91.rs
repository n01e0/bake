use anyhow::{anyhow, Result};

pub fn decode(input: &str) -> Result<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(String::new());
    }

    let bytes = base91::slice_decode(cleaned.as_bytes());
    String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn base91_decode() {
        assert_eq!(decode("TPwJh>A").unwrap(), "hello");
    }
}
