use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: Vec<u8>,
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
    brute_force(input, 1, top, min_score, None, None, &[]).unwrap_or_default()
}

pub fn brute_force(
    input: &[u8],
    key_bytes: usize,
    top: usize,
    min_score: f64,
    prefix: Option<&str>,
    suffix: Option<&str>,
    words: &[String],
) -> Result<Vec<Candidate>> {
    if input.is_empty() || top == 0 {
        return Ok(Vec::new());
    }

    if key_bytes == 0 {
        return Err(anyhow!("--key-bytes must be >= 1"));
    }
    if key_bytes > 3 {
        return Err(anyhow!(
            "--key-bytes > 3 is too expensive (search space grows as 256^N)"
        ));
    }

    let key_space = 256usize.pow(key_bytes as u32);
    let mut candidates = Vec::new();

    for idx in 0..key_space {
        let key = index_to_key(idx, key_bytes);
        let decoded = xor_with_key(input, &key)?;
        let plaintext = String::from_utf8_lossy(&decoded).to_string();

        if !matches_filters(&plaintext, prefix, suffix, words) {
            continue;
        }

        let score = english_score(&decoded);
        if score < min_score {
            continue;
        }

        candidates.push(Candidate {
            key,
            score,
            plaintext,
        });
    }

    candidates.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.key.cmp(&b.key)));
    candidates.truncate(top);
    Ok(candidates)
}

fn matches_filters(
    plaintext: &str,
    prefix: Option<&str>,
    suffix: Option<&str>,
    words: &[String],
) -> bool {
    if let Some(p) = prefix {
        if !plaintext.starts_with(p) {
            return false;
        }
    }
    if let Some(s) = suffix {
        if !plaintext.ends_with(s) {
            return false;
        }
    }
    for w in words {
        if !plaintext.contains(w) {
            return false;
        }
    }
    true
}

fn index_to_key(mut idx: usize, key_bytes: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_bytes];
    for i in (0..key_bytes).rev() {
        key[i] = (idx & 0xff) as u8;
        idx >>= 8;
    }
    key
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
    use super::{
        brute_force, brute_force_single_byte, format_output, parse_repeat_key, xor_with_key,
    };

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
        let results = brute_force_single_byte(&cipher, 5, 0.0);
        assert!(results.iter().any(|c| c.key == vec![0x42]));
        assert!(results.iter().any(|c| c.plaintext.contains("hello")));
    }

    #[test]
    fn brute_force_two_byte_key_with_prefix_filter() {
        let cipher = xor_with_key(b"hello world", &[0x12, 0x34]).unwrap();
        let results = brute_force(&cipher, 2, 10, 0.0, Some("hello"), None, &[]).unwrap();
        assert!(results
            .iter()
            .any(|c| c.key == vec![0x12, 0x34] && c.plaintext == "hello world"));
    }

    #[test]
    fn brute_force_word_and_suffix_filters() {
        let cipher = xor_with_key(b"flag{test}", &[0x42]).unwrap();
        let results = brute_force(
            &cipher,
            1,
            20,
            0.0,
            Some("flag{"),
            Some("}"),
            &["test".to_string()],
        )
        .unwrap();
        assert!(results.iter().any(|c| c.key == vec![0x42]));
    }

    #[test]
    fn invalid_key_bytes() {
        let err = brute_force(b"abc", 0, 5, 0.0, None, None, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("key-bytes"));

        let err = brute_force(b"abc", 4, 5, 0.0, None, None, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("too expensive"));
    }
}
