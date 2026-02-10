use anyhow::{anyhow, Result};
use quoted_printable::ParseMode;

pub fn decode(input: &str, strict: bool) -> Result<String> {
    let mode = if strict {
        ParseMode::Strict
    } else {
        ParseMode::Robust
    };

    let bytes = quoted_printable::decode(input.as_bytes(), mode)
        .map_err(|e| anyhow!("Can't decode quoted-printable: {e}"))?;
    String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn quoted_printable_decode() {
        assert_eq!(decode("hello=3Dworld", true).unwrap(), "hello=world");
    }
}
