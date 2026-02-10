use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use bzip2::{read::BzDecoder, write::BzEncoder, Compression as BzCompression};
use flate2::{
    read::{DeflateDecoder, ZlibDecoder},
    write::{DeflateEncoder, ZlibEncoder},
    Compression,
};
use std::io::{Read, Write};
use xz2::{read::XzDecoder, write::XzEncoder};

pub fn zlib_compress_to_base64(input: &[u8], no_padding: bool) -> Result<String> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    let compressed = encoder.finish()?;
    Ok(encode_b64(&compressed, no_padding))
}

pub fn zlib_decompress_from_base64(input: &str) -> Result<String> {
    let compressed = decode_b64(input)?;
    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    read_to_utf8(&mut decoder, "zlib")
}

pub fn deflate_compress_to_base64(input: &[u8], no_padding: bool) -> Result<String> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    let compressed = encoder.finish()?;
    Ok(encode_b64(&compressed, no_padding))
}

pub fn deflate_decompress_from_base64(input: &str) -> Result<String> {
    let compressed = decode_b64(input)?;
    let mut decoder = DeflateDecoder::new(compressed.as_slice());
    read_to_utf8(&mut decoder, "deflate")
}

pub fn bzip2_compress_to_base64(input: &[u8], no_padding: bool) -> Result<String> {
    let mut encoder = BzEncoder::new(Vec::new(), BzCompression::default());
    encoder.write_all(input)?;
    let compressed = encoder.finish()?;
    Ok(encode_b64(&compressed, no_padding))
}

pub fn bzip2_decompress_from_base64(input: &str) -> Result<String> {
    let compressed = decode_b64(input)?;
    let mut decoder = BzDecoder::new(compressed.as_slice());
    read_to_utf8(&mut decoder, "bzip2")
}

pub fn xz_compress_to_base64(input: &[u8], no_padding: bool) -> Result<String> {
    let mut encoder = XzEncoder::new(Vec::new(), 6);
    encoder.write_all(input)?;
    let compressed = encoder.finish()?;
    Ok(encode_b64(&compressed, no_padding))
}

pub fn xz_decompress_from_base64(input: &str) -> Result<String> {
    let compressed = decode_b64(input)?;
    let mut decoder = XzDecoder::new(compressed.as_slice());
    read_to_utf8(&mut decoder, "xz")
}

fn encode_b64(bytes: &[u8], no_padding: bool) -> String {
    if no_padding {
        general_purpose::STANDARD_NO_PAD.encode(bytes)
    } else {
        general_purpose::STANDARD.encode(bytes)
    }
}

fn decode_b64(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    general_purpose::STANDARD
        .decode(&cleaned)
        .or_else(|first_err| {
            let remainder = cleaned.len() % 4;
            if remainder == 0 {
                return Err(first_err);
            }
            let padded = format!("{cleaned}{}", "=".repeat(4 - remainder));
            general_purpose::STANDARD.decode(padded)
        })
        .map_err(|e| anyhow!("Can't decode base64: {e}"))
}

fn read_to_utf8(reader: &mut impl Read, label: &str) -> Result<String> {
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| anyhow!("Can't decompress {label} input: {e}"))?;
    String::from_utf8(out).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn zlib_roundtrip() {
        let encoded = zlib_compress_to_base64(b"hello", false).unwrap();
        assert_eq!(zlib_decompress_from_base64(&encoded).unwrap(), "hello");
    }

    #[test]
    fn deflate_roundtrip() {
        let encoded = deflate_compress_to_base64(b"hello", true).unwrap();
        assert_eq!(deflate_decompress_from_base64(&encoded).unwrap(), "hello");
    }

    #[test]
    fn bzip2_roundtrip() {
        let encoded = bzip2_compress_to_base64(b"hello", false).unwrap();
        assert_eq!(bzip2_decompress_from_base64(&encoded).unwrap(), "hello");
    }

    #[test]
    fn xz_roundtrip() {
        let encoded = xz_compress_to_base64(b"hello", false).unwrap();
        assert_eq!(xz_decompress_from_base64(&encoded).unwrap(), "hello");
    }

    #[test]
    fn invalid_base64() {
        let err = zlib_decompress_from_base64("@@@").unwrap_err().to_string();
        assert!(err.contains("Can't decode base64"));
    }
}
