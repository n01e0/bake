use anyhow::{anyhow, Result};

pub fn decode(input: &str) -> Result<String> {
    let delimiters = &[",", "\r", "\n", ";", ":", " ", "\t"];
    let prefixes = &["0b", "\\b", "b"];

    let mut cleaned_input = input.to_string();

    for delim in delimiters {
        cleaned_input = cleaned_input.replace(delim, "");
    }

    for prefix in prefixes {
        cleaned_input = cleaned_input.replace(prefix, "");
    }

    if cleaned_input.is_empty() {
        return Ok(String::new());
    }

    if !cleaned_input.chars().all(|ch| ch == '0' || ch == '1') {
        return Err(anyhow!(
            "Input contains non-binary characters: '{cleaned_input}'"
        ));
    }

    if !cleaned_input.len().is_multiple_of(8) {
        return Err(anyhow!(
            "Input length is not a multiple of 8: '{}'",
            cleaned_input
        ));
    }

    let mut bytes = Vec::new();

    for (i, chunk) in cleaned_input.as_bytes().chunks(8).enumerate() {
        let binary_str =
            std::str::from_utf8(chunk).map_err(|e| anyhow!("Failed to read chunk: {e}"))?;
        let byte = u8::from_str_radix(binary_str, 2).map_err(|_| {
            anyhow!(
                "Failed to parse '{}' at index: {}. Successfully converted part: '{}'",
                binary_str,
                i,
                String::from_utf8(bytes.clone()).unwrap_or_default()
            )
        })?;
        bytes.push(byte);
    }

    match String::from_utf8(bytes.clone()) {
        Ok(string) => Ok(string),
        Err(e) => {
            let valid_up_to = e.utf8_error().valid_up_to();
            let successful_string =
                String::from_utf8(bytes[..valid_up_to].to_vec()).unwrap_or_default();
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
    fn plain_binary() {
        assert_eq!(decode("0100000101000010").unwrap(), "AB");
    }

    #[test]
    fn delimiter_and_prefix() {
        assert_eq!(decode("0b01000001 0b01000010").unwrap(), "AB");
    }

    #[test]
    fn mixed_delimiters() {
        assert_eq!(decode("\\b01000001,0b01000010\n01000011").unwrap(), "ABC");
    }

    #[test]
    fn invalid_character() {
        let err = decode("0100002").unwrap_err().to_string();
        assert!(err.contains("non-binary"));
    }

    #[test]
    fn invalid_length() {
        let err = decode("0100001").unwrap_err().to_string();
        assert!(err.contains("multiple of 8"));
    }

    #[test]
    fn invalid_utf8() {
        let err = decode("10000000").unwrap_err().to_string();
        assert!(err.contains("UTF-8 conversion error"));
    }

    #[test]
    fn empty_input() {
        assert_eq!(decode("\n\r \t").unwrap(), "");
    }
}
