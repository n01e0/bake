use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: u8,
    pub score: f64,
    pub plaintext: String,
}

pub fn xor_with_key(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(anyhow!("Key must not be empty"));
    }

    Ok(input
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect())
}

pub fn parse_repeat_key(key: &str, hex_key: bool) -> Result<Vec<u8>> {
    if hex_key {
        parse_hex_bytes(key)
    } else {
        if key.is_empty() {
            return Err(anyhow!("Key must not be empty"));
        }
        Ok(key.as_bytes().to_vec())
    }
}

pub fn format_output(bytes: &[u8], output_hex: bool) -> String {
    if output_hex {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

pub fn brute_force_single_byte(input: &[u8], top: usize, min_score: f64) -> Vec<Candidate> {
    if input.is_empty() || top == 0 {
        return Vec::new();
    }

    let mut candidates: Vec<Candidate> = (0u16..=255)
        .map(|k| {
            let key = k as u8;
            let decoded: Vec<u8> = input.iter().map(|b| b ^ key).collect();
            let score = english_score(&decoded);
            Candidate {
                key,
                score,
                plaintext: String::from_utf8_lossy(&decoded).to_string(),
            }
        })
        .filter(|c| c.score >= min_score)
        .collect();

    candidates.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.key.cmp(&b.key)));
    candidates.truncate(top);
    candidates
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();

    if cleaned.is_empty() {
        return Err(anyhow!("Key must not be empty"));
    }

    if !cleaned.len().is_multiple_of(2) {
        return Err(anyhow!("Hex key length must be even"));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).map_err(|e| anyhow!("Invalid UTF-8 in key: {e}"))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| anyhow!("Invalid hex pair '{pair}' in key"))?;
        out.push(byte);
    }

    Ok(out)
}

fn english_score(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut score = 0.0;
    for &b in bytes {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' => score += 2.0,
            b' ' => score += 3.0,
            b'0'..=b'9' => score += 0.7,
            b'.' | b',' | b'!' | b'?' | b'\'' | b'"' | b';' | b':' | b'-' | b'(' | b')' => {
                score += 0.4
            }
            b'\n' | b'\r' | b'\t' => score += 0.2,
            0x21..=0x7e => score += 0.1,
            _ => score -= 5.0,
        }
    }

    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for common in [" the ", " and ", " to ", " of ", " in "] {
        if lower.contains(common) {
            score += 8.0;
        }
    }

    score / bytes.len() as f64
}

#[cfg(test)]
mod test {
    use super::{brute_force_single_byte, format_output, parse_repeat_key, xor_with_key};

    #[test]
    fn xor_single_byte() {
        let out = xor_with_key(b"hello", &[0x20]).unwrap();
        assert_eq!(out, b"HELLO");
    }

    #[test]
    fn xor_repeat_key_hex_output() {
        let out = xor_with_key(b"attack at dawn", b"ICE").unwrap();
        assert_eq!(format_output(&out, true), "28373128202e6922316927243e2d");
    }

    #[test]
    fn parse_hex_key() {
        let key = parse_repeat_key("49 43 45", true).unwrap();
        assert_eq!(key, b"ICE");
    }

    #[test]
    fn parse_hex_key_error() {
        let err = parse_repeat_key("abc", true).unwrap_err().to_string();
        assert!(err.contains("even"));
    }

    #[test]
    fn brute_force_finds_key() {
        let cipher = xor_with_key(b"hello world", &[0x42]).unwrap();
        let results = brute_force_single_byte(&cipher, 3, 0.0);
        assert_eq!(results[0].key, 0x42);
        assert!(results[0].plaintext.contains("hello"));
    }
}
