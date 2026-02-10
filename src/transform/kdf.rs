use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;

pub fn pbkdf2_sha256(
    password: &str,
    salt: &str,
    hex_salt: bool,
    iterations: u32,
    dk_len: usize,
) -> Result<String> {
    let salt_bytes = parse_salt(salt, hex_salt)?;
    if dk_len == 0 {
        return Err(anyhow!("Derived key length must be > 0"));
    }
    let mut out = vec![0u8; dk_len];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, iterations, &mut out);
    Ok(hex_lower(&out))
}

pub fn scrypt_derive(
    password: &str,
    salt: &str,
    hex_salt: bool,
    log_n: u8,
    r: u32,
    p: u32,
    dk_len: usize,
) -> Result<String> {
    let salt_bytes = parse_salt(salt, hex_salt)?;
    if dk_len == 0 {
        return Err(anyhow!("Derived key length must be > 0"));
    }
    let params = ScryptParams::new(log_n, r, p, dk_len)
        .map_err(|e| anyhow!("Invalid scrypt params: {e}"))?;
    let mut out = vec![0u8; dk_len];
    scrypt(password.as_bytes(), &salt_bytes, &params, &mut out)
        .map_err(|e| anyhow!("scrypt error: {e}"))?;
    Ok(hex_lower(&out))
}

pub fn argon2id_derive(
    password: &str,
    salt: &str,
    hex_salt: bool,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    dk_len: usize,
) -> Result<String> {
    let salt_bytes = parse_salt(salt, hex_salt)?;
    if dk_len == 0 {
        return Err(anyhow!("Derived key length must be > 0"));
    }

    let params = Params::new(memory_kib, iterations, parallelism, Some(dk_len))
        .map_err(|e| anyhow!("Invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = vec![0u8; dk_len];
    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut out)
        .map_err(|e| anyhow!("argon2 error: {e}"))?;

    Ok(hex_lower(&out))
}

fn parse_salt(salt: &str, hex_salt: bool) -> Result<Vec<u8>> {
    if hex_salt {
        parse_hex(salt)
    } else {
        Ok(salt.as_bytes().to_vec())
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();

    if cleaned.is_empty() {
        return Err(anyhow!("Salt must not be empty"));
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

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod test {
    use super::{argon2id_derive, pbkdf2_sha256, scrypt_derive};

    #[test]
    fn pbkdf2_known_len() {
        let out = pbkdf2_sha256("password", "salt", false, 1, 32).unwrap();
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn scrypt_known_len() {
        let out = scrypt_derive("password", "salt", false, 10, 8, 1, 32).unwrap();
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn argon2_known_len() {
        let out = argon2id_derive("password", "somesalt", false, 19456, 2, 1, 32).unwrap();
        assert_eq!(out.len(), 64);
    }
}
