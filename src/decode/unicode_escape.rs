use anyhow::{anyhow, Result};

pub fn decode(input: &str) -> Result<String> {
    let mut units = Vec::new();
    let mut i = 0;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        if i + 6 <= bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'u' {
            let hex = &input[i + 2..i + 6];
            let unit = u16::from_str_radix(hex, 16)
                .map_err(|_| anyhow!("Invalid unicode escape sequence: \\u{hex}"))?;
            units.push(unit);
            i += 6;
        } else {
            let ch = input[i..]
                .chars()
                .next()
                .ok_or_else(|| anyhow!("Invalid UTF-8 boundary"))?;
            let mut buf = [0u16; 2];
            let encoded = ch.encode_utf16(&mut buf);
            units.extend(encoded.iter().copied());
            i += ch.len_utf8();
        }
    }

    String::from_utf16(&units).map_err(|e| anyhow!("UTF-16 decode error: {e}"))
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn unicode_escape_decode() {
        assert_eq!(decode("\\u0041\\u3042").unwrap(), "Aあ");
    }

    #[test]
    fn invalid_escape() {
        let err = decode("\\uZZZZ").unwrap_err().to_string();
        assert!(err.contains("Invalid unicode escape"));
    }
}
