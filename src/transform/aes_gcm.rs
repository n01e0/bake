use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};

pub fn encrypt_to_base64(
    plaintext: &[u8],
    key_hex: &str,
    nonce_hex: &str,
    aad: &str,
    no_padding: bool,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let nonce = parse_hex(nonce_hex)?;

    if key.len() != 32 {
        return Err(anyhow!("AES-256-GCM key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(anyhow!("AES-GCM nonce must be 12 bytes"));
    }

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("Invalid key: {e}"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    Ok(if no_padding {
        general_purpose::STANDARD_NO_PAD.encode(ciphertext)
    } else {
        general_purpose::STANDARD.encode(ciphertext)
    })
}

pub fn decrypt_from_base64(
    ciphertext_b64: &str,
    key_hex: &str,
    nonce_hex: &str,
    aad: &str,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let nonce = parse_hex(nonce_hex)?;

    if key.len() != 32 {
        return Err(anyhow!("AES-256-GCM key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(anyhow!("AES-GCM nonce must be 12 bytes"));
    }

    let cleaned: String = ciphertext_b64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let ciphertext = decode_base64_with_optional_padding(&cleaned)
        .map_err(|e| anyhow!("Can't decode base64: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("Invalid key: {e}"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| anyhow!("Decryption failed: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

fn parse_hex(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();

    if !cleaned.len().is_multiple_of(2) {
        return Err(anyhow!("Hex input length must be even"));
    }

    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).map_err(|e| anyhow!("Invalid hex bytes: {e}"))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| anyhow!("Invalid hex pair '{pair}' in input"))?;
        bytes.push(byte);
    }

    Ok(bytes)
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
    use super::{decrypt_from_base64, encrypt_to_base64};

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NONCE: &str = "1a1b1c1d1e1f202122232425";

    #[test]
    fn roundtrip() {
        let encrypted = encrypt_to_base64(b"hello", KEY, NONCE, "", false).unwrap();
        assert_eq!(
            decrypt_from_base64(&encrypted, KEY, NONCE, "").unwrap(),
            "hello"
        );
    }

    #[test]
    fn roundtrip_with_aad_and_no_padding() {
        let encrypted = encrypt_to_base64(b"hello", KEY, NONCE, "meta", true).unwrap();
        assert!(!encrypted.ends_with('='));
        assert_eq!(
            decrypt_from_base64(&encrypted, KEY, NONCE, "meta").unwrap(),
            "hello"
        );
    }

    #[test]
    fn invalid_key_length() {
        let err = encrypt_to_base64(b"hello", "00", NONCE, "", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("key must be 32 bytes"));
    }

    #[test]
    fn invalid_nonce_length() {
        let err = encrypt_to_base64(b"hello", KEY, "00", "", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nonce must be 12 bytes"));
    }

    #[test]
    fn invalid_base64() {
        let err = decrypt_from_base64("@@@", KEY, NONCE, "")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Can't decode base64"));
    }

    #[test]
    fn authentication_failure() {
        let encrypted = encrypt_to_base64(b"hello", KEY, NONCE, "", false).unwrap();
        let wrong_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let err = decrypt_from_base64(&encrypted, wrong_key, NONCE, "")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Decryption failed"));
    }

    #[test]
    fn invalid_utf8_after_decryption() {
        let encrypted = encrypt_to_base64(&[0x80], KEY, NONCE, "", false).unwrap();
        let err = decrypt_from_base64(&encrypted, KEY, NONCE, "")
            .unwrap_err()
            .to_string();
        assert!(err.contains("UTF-8 conversion error"));
    }
}
