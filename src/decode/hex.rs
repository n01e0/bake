use anyhow::{anyhow, Result};

pub fn decode(input: &str) -> Result<String> {
    let delimiters = &[",", "\r", "\n", ";", ":", " ", "\t"];
    let prefixes = &["%", "0x", "x", "\\"];

    let mut cleaned_input = input.to_string();

    for delim in delimiters {
        cleaned_input = cleaned_input.replace(delim, "");
    }

    for prefix in prefixes {
        cleaned_input = cleaned_input.replace(prefix, "");
    }

    if !cleaned_input.len().is_multiple_of(2) {
        return Err(anyhow!("Input length is not even: '{}'", cleaned_input));
    }

    let mut bytes = Vec::new();

    for (i, chunk) in cleaned_input.as_bytes().chunks(2).enumerate() {
        let hex_str =
            std::str::from_utf8(chunk).map_err(|e| anyhow!("Failed to read chunk: {}", e))?;
        let byte = u8::from_str_radix(hex_str, 16).map_err(|_| {
            anyhow!(
                "Failed to parse '{}' at index: {}. Successfully converted part: '{}'",
                hex_str,
                i,
                String::from_utf8(bytes.clone()).unwrap()
            )
        })?;
        bytes.push(byte);
    }

    match String::from_utf8(bytes.clone()) {
        Ok(string) => Ok(string),
        Err(e) => {
            let valid_up_to = e.utf8_error().valid_up_to();
            let successful_string =
                String::from_utf8(bytes[0..valid_up_to].to_vec()).unwrap_or_default();
            Err(anyhow!(
                "UTF-8 conversion error: {}. Successfully converted part: '{}'",
                e,
                successful_string
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn space_delim() {
        let hex = "66 6f 6f 62 61 72";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);

        let hex = " 66 6f 6f 62 61 72";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn comma_delim() {
        let hex = "66,6f,6f,62,61,72";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn percent_delim() {
        let hex = "%66%6f%6f%62%61%72";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn semicolon_delim() {
        let hex = "66;6f;6f;62;61;72;";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn colon_delim() {
        let hex = "66:6f:6f:62:61:72:";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn crlf_delim() {
        let hex = "66\r\n6f\r\n6f\r\n62\r\n61\r\n72\r\n";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn lf_delim() {
        let hex = "66\n6f\n6f\n62\n61\n72\n";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn x_delim() {
        let hex = "0x66,0x6f,0x6f,0x62,0x61,0x72";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);

        let hex = "\\x66\\x6f\\x6f\\x62\\x61\\x72";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn multi_pattern() {
        let hex = "\\x66,\\x6f,\\x6f,\\x62,\\x61,\\x72,";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
        let hex = "0x66,0x6f,0x6f,0x62,0x61,0x72 ";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn mixed_pattern() {
        let hex = "\\x66,0x6f x6f;%62, 61:72\r\n";
        let parsed = decode(hex).unwrap();
        assert_eq!("foobar", &parsed[..]);
    }

    #[test]
    fn error_pattern() {
        let invalid = "%65ZZ";
        let parsed = decode(invalid);
        assert!(parsed.is_err());
        assert_eq!(
            "Failed to parse 'ZZ' at index: 1. Successfully converted part: 'e'",
            &parsed.unwrap_err().to_string()[..]
        );
        let hex = "%65%72%72%6f%72%80%41";
        let parsed = decode(hex);
        assert!(parsed.is_err());
        assert_eq!("UTF-8 conversion error: invalid utf-8 sequence of 1 bytes from index 5. Successfully converted part: 'error'", &parsed.unwrap_err().to_string()[..]);
    }
}
