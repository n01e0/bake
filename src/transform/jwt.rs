use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::{json, Value};

pub fn decode_unverified(token: &str) -> Result<String> {
    let (header, payload, signature) = split_jwt(token)?;

    let header_json: Value = serde_json::from_slice(&decode_base64url(header)?)
        .map_err(|e| anyhow!("Invalid JWT header JSON: {e}"))?;
    let payload_json: Value = serde_json::from_slice(&decode_base64url(payload)?)
        .map_err(|e| anyhow!("Invalid JWT payload JSON: {e}"))?;

    let obj = json!({
        "header": header_json,
        "payload": payload_json,
        "signature_b64url": signature,
    });

    serde_json::to_string_pretty(&obj).map_err(|e| anyhow!("JSON format error: {e}"))
}

pub fn verify_hs256(token: &str, key: &str) -> Result<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let data = decode::<Value>(
        token,
        &DecodingKey::from_secret(key.as_bytes()),
        &validation,
    )
    .map_err(|e| anyhow!("JWT verification failed (HS256): {e}"))?;

    serde_json::to_string_pretty(&data.claims).map_err(|e| anyhow!("JSON format error: {e}"))
}

pub fn verify_rs256(token: &str, public_key_pem: &str) -> Result<String> {
    let key = std::fs::read(public_key_pem)
        .map_err(|e| anyhow!("Failed to read public key PEM file: {e}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let data = decode::<Value>(
        token,
        &DecodingKey::from_rsa_pem(&key).map_err(|e| anyhow!("Invalid RSA public key PEM: {e}"))?,
        &validation,
    )
    .map_err(|e| anyhow!("JWT verification failed (RS256): {e}"))?;

    serde_json::to_string_pretty(&data.claims).map_err(|e| anyhow!("JSON format error: {e}"))
}

fn split_jwt(token: &str) -> Result<(&str, &str, &str)> {
    let mut parts = token.trim().split('.');
    let h = parts.next().ok_or_else(|| anyhow!("Invalid JWT format"))?;
    let p = parts.next().ok_or_else(|| anyhow!("Invalid JWT format"))?;
    let s = parts.next().ok_or_else(|| anyhow!("Invalid JWT format"))?;
    if parts.next().is_some() {
        return Err(anyhow!("Invalid JWT format"));
    }
    Ok((h, p, s))
}

fn decode_base64url(input: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|first_err| {
            let remainder = input.len() % 4;
            if remainder == 0 {
                return Err(first_err);
            }
            let padded = format!("{input}{}", "=".repeat(4 - remainder));
            general_purpose::URL_SAFE_NO_PAD.decode(padded)
        })
        .map_err(|e| anyhow!("Invalid base64url segment: {e}"))
}

#[cfg(test)]
mod test {
    use super::{decode_unverified, verify_hs256};

    #[test]
    fn decode_unverified_works() {
        // header: {"alg":"HS256","typ":"JWT"}
        // payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let out = decode_unverified(token).unwrap();
        assert!(out.contains("John Doe"));
    }

    #[test]
    fn verify_hs256_works() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let out = verify_hs256(token, "your-256-bit-secret").unwrap();
        assert!(out.contains("John Doe"));
    }
}
