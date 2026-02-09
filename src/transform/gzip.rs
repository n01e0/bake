use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};

pub fn compress_to_base64(input: &[u8], no_padding: bool) -> Result<String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    let compressed = encoder.finish()?;

    let output = if no_padding {
        general_purpose::STANDARD_NO_PAD.encode(compressed)
    } else {
        general_purpose::STANDARD.encode(compressed)
    };

    Ok(output)
}

pub fn decompress_from_base64(input: &str) -> Result<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(String::new());
    }

    let compressed = decode_base64_with_optional_padding(&cleaned)
        .map_err(|e| anyhow!("Can't decode base64: {e}"))?;

    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| anyhow!("Can't gunzip input: {e}"))?;

    String::from_utf8(decompressed).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

fn decode_base64_with_optional_padding(
    input: &str,
) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD
        .decode(input)
        .or_else(|first_err| {
            let remainder = input.len() % 4;
            if remainder == 0 {
                return Err(first_err);
            }
            let padded = format!("{input}{}", "=".repeat(4 - remainder));
            general_purpose::STANDARD.decode(padded)
        })
}

#[cfg(test)]
mod test {
    use super::{compress_to_base64, decompress_from_base64};

    #[test]
    fn roundtrip_standard() {
        let encoded = compress_to_base64(b"hello", false).unwrap();
        assert_eq!(decompress_from_base64(&encoded).unwrap(), "hello");
    }

    #[test]
    fn roundtrip_no_padding() {
        let encoded = compress_to_base64(b"hello", true).unwrap();
        assert!(!encoded.ends_with('='));
        assert_eq!(decompress_from_base64(&encoded).unwrap(), "hello");
    }

    #[test]
    fn accepts_whitespace() {
        let encoded = compress_to_base64(b"hello", false).unwrap();
        let with_ws = format!(
            "{}\n{}",
            &encoded[..encoded.len() / 2],
            &encoded[encoded.len() / 2..]
        );
        assert_eq!(decompress_from_base64(&with_ws).unwrap(), "hello");
    }

    #[test]
    fn invalid_base64() {
        let err = decompress_from_base64("@@@").unwrap_err().to_string();
        assert!(err.contains("Can't decode base64"));
    }

    #[test]
    fn invalid_gzip_payload() {
        let err = decompress_from_base64("aGVsbG8=").unwrap_err().to_string();
        assert!(err.contains("Can't gunzip input"));
    }

    #[test]
    fn invalid_utf8_payload() {
        let encoded = compress_to_base64(&[0x80], false).unwrap();
        let err = decompress_from_base64(&encoded).unwrap_err().to_string();
        assert!(err.contains("UTF-8 conversion error"));
    }

    #[test]
    fn empty_input() {
        assert_eq!(decompress_from_base64("\n\r ").unwrap(), "");
    }
}
