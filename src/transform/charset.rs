use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use encoding_rs::{EUC_JP, SHIFT_JIS};

use crate::commands::{BinaryFormat, Charset};

pub fn encode_from_utf8(input: &str, to: Charset) -> Result<Vec<u8>> {
    match to {
        Charset::Utf8 => Ok(input.as_bytes().to_vec()),
        Charset::Utf16le => Ok(input
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>()),
        Charset::Utf16be => Ok(input
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect::<Vec<_>>()),
        Charset::ShiftJis => encode_with_legacy_charset(input, SHIFT_JIS, "Shift_JIS"),
        Charset::EucJp => encode_with_legacy_charset(input, EUC_JP, "EUC-JP"),
    }
}

pub fn decode_to_utf8(bytes: &[u8], from: Charset) -> Result<String> {
    match from {
        Charset::Utf8 => {
            String::from_utf8(bytes.to_vec()).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
        }
        Charset::Utf16le => decode_utf16_bytes(bytes, true),
        Charset::Utf16be => decode_utf16_bytes(bytes, false),
        Charset::ShiftJis => decode_with_legacy_charset(bytes, SHIFT_JIS, "Shift_JIS"),
        Charset::EucJp => decode_with_legacy_charset(bytes, EUC_JP, "EUC-JP"),
    }
}

pub fn parse_input_bytes(input: &str, format: BinaryFormat) -> Result<Vec<u8>> {
    match format {
        BinaryFormat::Hex => parse_hex(input),
        BinaryFormat::Base64 => {
            let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            decode_base64_with_optional_padding(&cleaned)
                .map_err(|e| anyhow!("Can't decode base64 input: {e}"))
        }
    }
}

pub fn format_output_bytes(bytes: &[u8], format: BinaryFormat) -> String {
    match format {
        BinaryFormat::Hex => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        BinaryFormat::Base64 => general_purpose::STANDARD.encode(bytes),
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();

    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    if !cleaned.len().is_multiple_of(2) {
        return Err(anyhow!("Hex input length must be even"));
    }

    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair =
            std::str::from_utf8(chunk).map_err(|e| anyhow!("Invalid UTF-8 in hex input: {e}"))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| anyhow!("Invalid hex pair '{pair}' in input"))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

fn encode_with_legacy_charset(
    input: &str,
    encoding: &'static encoding_rs::Encoding,
    label: &str,
) -> Result<Vec<u8>> {
    let (bytes, _enc_used, had_errors) = encoding.encode(input);
    if had_errors {
        return Err(anyhow!(
            "Can't encode string in {label}: unrepresentable characters"
        ));
    }
    Ok(bytes.into_owned())
}

fn decode_with_legacy_charset(
    bytes: &[u8],
    encoding: &'static encoding_rs::Encoding,
    label: &str,
) -> Result<String> {
    let (text, had_errors) = encoding.decode_without_bom_handling(bytes);
    if had_errors {
        return Err(anyhow!(
            "Can't decode bytes as {label}: invalid byte sequence"
        ));
    }
    Ok(text.into_owned())
}

fn decode_utf16_bytes(bytes: &[u8], little_endian: bool) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(anyhow!("UTF-16 byte length must be even"));
    }

    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();

    String::from_utf16(&units).map_err(|e| anyhow!("UTF-16 decode error: {e}"))
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
    use super::{decode_to_utf8, encode_from_utf8, format_output_bytes, parse_input_bytes};
    use crate::commands::{BinaryFormat, Charset};

    #[test]
    fn utf16le_encode_hex() {
        let bytes = encode_from_utf8("Aあ", Charset::Utf16le).unwrap();
        assert_eq!(format_output_bytes(&bytes, BinaryFormat::Hex), "41004230");
    }

    #[test]
    fn utf16be_decode_hex() {
        let bytes = parse_input_bytes("00413042", BinaryFormat::Hex).unwrap();
        assert_eq!(decode_to_utf8(&bytes, Charset::Utf16be).unwrap(), "Aあ");
    }

    #[test]
    fn shift_jis_roundtrip() {
        let bytes = encode_from_utf8("こんにちは", Charset::ShiftJis).unwrap();
        assert_eq!(
            decode_to_utf8(&bytes, Charset::ShiftJis).unwrap(),
            "こんにちは"
        );
    }

    #[test]
    fn euc_jp_roundtrip() {
        let bytes = encode_from_utf8("こんにちは", Charset::EucJp).unwrap();
        assert_eq!(
            decode_to_utf8(&bytes, Charset::EucJp).unwrap(),
            "こんにちは"
        );
    }

    #[test]
    fn invalid_utf16_length() {
        let err = decode_to_utf8(&[0x00], Charset::Utf16le)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be even"));
    }

    #[test]
    fn invalid_hex_input() {
        let err = parse_input_bytes("zz", BinaryFormat::Hex)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid hex pair"));
    }

    #[test]
    fn invalid_shift_jis_decode() {
        let err = decode_to_utf8(&[0x82], Charset::ShiftJis)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Can't decode bytes as Shift_JIS"));
    }
}
