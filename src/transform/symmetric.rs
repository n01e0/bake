use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};

pub fn encrypt_aes_cbc_to_base64(
    plaintext: &[u8],
    key_hex: &str,
    iv_hex: &str,
    no_padding: bool,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let iv = parse_hex(iv_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("AES-256 key must be 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(anyhow!("AES-CBC IV must be 16 bytes"));
    }

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    let ciphertext = Aes256CbcEnc::new_from_slices(&key, &iv)
        .map_err(|e| anyhow!("Invalid key/iv: {e}"))?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok(encode_b64(&ciphertext, no_padding))
}

pub fn decrypt_aes_cbc_from_base64(
    ciphertext_b64: &str,
    key_hex: &str,
    iv_hex: &str,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let iv = parse_hex(iv_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("AES-256 key must be 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(anyhow!("AES-CBC IV must be 16 bytes"));
    }

    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    let ciphertext = decode_b64(ciphertext_b64)?;
    let plaintext = Aes256CbcDec::new_from_slices(&key, &iv)
        .map_err(|e| anyhow!("Invalid key/iv: {e}"))?
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|e| anyhow!("AES-CBC decrypt error: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

pub fn encrypt_aes_ecb_to_base64(
    plaintext: &[u8],
    key_hex: &str,
    no_padding: bool,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("AES-256 key must be 32 bytes"));
    }

    type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;
    let ciphertext = Aes256EcbEnc::new_from_slice(&key)
        .map_err(|e| anyhow!("Invalid key: {e}"))?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok(encode_b64(&ciphertext, no_padding))
}

pub fn decrypt_aes_ecb_from_base64(ciphertext_b64: &str, key_hex: &str) -> Result<String> {
    let key = parse_hex(key_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("AES-256 key must be 32 bytes"));
    }

    type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
    let ciphertext = decode_b64(ciphertext_b64)?;
    let plaintext = Aes256EcbDec::new_from_slice(&key)
        .map_err(|e| anyhow!("Invalid key: {e}"))?
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|e| anyhow!("AES-ECB decrypt error: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

pub fn encrypt_aes_ctr_to_base64(
    plaintext: &[u8],
    key_hex: &str,
    iv_hex: &str,
    no_padding: bool,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let iv = parse_hex(iv_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("AES-256 key must be 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(anyhow!("AES-CTR IV must be 16 bytes"));
    }

    type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
    let mut data = plaintext.to_vec();
    let mut cipher =
        Aes256Ctr::new_from_slices(&key, &iv).map_err(|e| anyhow!("Invalid key/iv: {e}"))?;
    cipher.apply_keystream(&mut data);
    Ok(encode_b64(&data, no_padding))
}

pub fn decrypt_aes_ctr_from_base64(
    ciphertext_b64: &str,
    key_hex: &str,
    iv_hex: &str,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let iv = parse_hex(iv_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("AES-256 key must be 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(anyhow!("AES-CTR IV must be 16 bytes"));
    }

    type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
    let mut data = decode_b64(ciphertext_b64)?;
    let mut cipher =
        Aes256Ctr::new_from_slices(&key, &iv).map_err(|e| anyhow!("Invalid key/iv: {e}"))?;
    cipher.apply_keystream(&mut data);
    String::from_utf8(data).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

pub fn encrypt_chacha20_to_base64(
    plaintext: &[u8],
    key_hex: &str,
    nonce_hex: &str,
    no_padding: bool,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let nonce = parse_hex(nonce_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("ChaCha20 key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(anyhow!("ChaCha20 nonce must be 12 bytes"));
    }

    let mut data = plaintext.to_vec();
    let mut cipher = chacha20::ChaCha20::new_from_slices(&key, &nonce)
        .map_err(|e| anyhow!("Invalid key/nonce: {e}"))?;
    cipher.apply_keystream(&mut data);
    Ok(encode_b64(&data, no_padding))
}

pub fn decrypt_chacha20_from_base64(
    ciphertext_b64: &str,
    key_hex: &str,
    nonce_hex: &str,
) -> Result<String> {
    let key = parse_hex(key_hex)?;
    let nonce = parse_hex(nonce_hex)?;
    if key.len() != 32 {
        return Err(anyhow!("ChaCha20 key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(anyhow!("ChaCha20 nonce must be 12 bytes"));
    }

    let mut data = decode_b64(ciphertext_b64)?;
    let mut cipher = chacha20::ChaCha20::new_from_slices(&key, &nonce)
        .map_err(|e| anyhow!("Invalid key/nonce: {e}"))?;
    cipher.apply_keystream(&mut data);
    String::from_utf8(data).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

pub fn encrypt_rc4_to_base64(
    plaintext: &[u8],
    key: &str,
    hex_key: bool,
    no_padding: bool,
) -> Result<String> {
    let key_bytes = if hex_key {
        parse_hex(key)?
    } else {
        key.as_bytes().to_vec()
    };
    if key_bytes.is_empty() {
        return Err(anyhow!("RC4 key must not be empty"));
    }

    let mut data = plaintext.to_vec();
    let mut cipher = arc4::Arc4::with_key(&key_bytes);
    cipher.encrypt(&mut data);
    Ok(encode_b64(&data, no_padding))
}

pub fn decrypt_rc4_from_base64(ciphertext_b64: &str, key: &str, hex_key: bool) -> Result<String> {
    let key_bytes = if hex_key {
        parse_hex(key)?
    } else {
        key.as_bytes().to_vec()
    };
    if key_bytes.is_empty() {
        return Err(anyhow!("RC4 key must not be empty"));
    }

    let mut data = decode_b64(ciphertext_b64)?;
    let mut cipher = arc4::Arc4::with_key(&key_bytes);
    cipher.encrypt(&mut data);
    String::from_utf8(data).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
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

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).map_err(|e| anyhow!("Invalid hex: {e}"))?;
        let b = u8::from_str_radix(pair, 16).map_err(|_| anyhow!("Invalid hex pair '{pair}'"))?;
        out.push(b);
    }
    Ok(out)
}

fn encode_b64(data: &[u8], no_padding: bool) -> String {
    if no_padding {
        general_purpose::STANDARD_NO_PAD.encode(data)
    } else {
        general_purpose::STANDARD.encode(data)
    }
}

fn decode_b64(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
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

#[cfg(test)]
mod test {
    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const IV16: &str = "1a1b1c1d1e1f20212223242526272829";
    const NONCE12: &str = "1a1b1c1d1e1f202122232425";

    #[test]
    fn aes_cbc_roundtrip() {
        let enc = encrypt_aes_cbc_to_base64(b"hello", KEY, IV16, false).unwrap();
        assert_eq!(
            decrypt_aes_cbc_from_base64(&enc, KEY, IV16).unwrap(),
            "hello"
        );
    }

    #[test]
    fn aes_ctr_roundtrip() {
        let enc = encrypt_aes_ctr_to_base64(b"hello", KEY, IV16, false).unwrap();
        assert_eq!(
            decrypt_aes_ctr_from_base64(&enc, KEY, IV16).unwrap(),
            "hello"
        );
    }

    #[test]
    fn aes_ecb_roundtrip() {
        let enc = encrypt_aes_ecb_to_base64(b"hello", KEY, false).unwrap();
        assert_eq!(decrypt_aes_ecb_from_base64(&enc, KEY).unwrap(), "hello");
    }

    #[test]
    fn chacha20_roundtrip() {
        let enc = encrypt_chacha20_to_base64(b"hello", KEY, NONCE12, false).unwrap();
        assert_eq!(
            decrypt_chacha20_from_base64(&enc, KEY, NONCE12).unwrap(),
            "hello"
        );
    }

    #[test]
    fn rc4_roundtrip() {
        let enc = encrypt_rc4_to_base64(b"hello", "secret", false, false).unwrap();
        assert_eq!(
            decrypt_rc4_from_base64(&enc, "secret", false).unwrap(),
            "hello"
        );
    }
}
