use anyhow::{anyhow, Result};
use crc::{Crc, CRC_32_ISO_HDLC, CRC_64_ECMA_182};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::commands::{CrcAlgorithm, HmacAlgorithm};

pub fn hmac_digest(
    input: &[u8],
    key: &str,
    hex_key: bool,
    algorithm: HmacAlgorithm,
) -> Result<String> {
    let key_bytes = if hex_key {
        parse_hex_key(key)?
    } else {
        key.as_bytes().to_vec()
    };

    if key_bytes.is_empty() {
        return Err(anyhow!("HMAC key must not be empty"));
    }

    let bytes = match algorithm {
        HmacAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
                .map_err(|e| anyhow!("Invalid HMAC key: {e}"))?;
            mac.update(input);
            mac.finalize().into_bytes().to_vec()
        }
        HmacAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&key_bytes)
                .map_err(|e| anyhow!("Invalid HMAC key: {e}"))?;
            mac.update(input);
            mac.finalize().into_bytes().to_vec()
        }
    };

    Ok(hex_lower(&bytes))
}

pub fn crc_digest(input: &[u8], algorithm: CrcAlgorithm) -> String {
    match algorithm {
        CrcAlgorithm::Crc32 => {
            let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
            format!("{:08x}", crc.checksum(input))
        }
        CrcAlgorithm::Crc64 => {
            let crc = Crc::<u64>::new(&CRC_64_ECMA_182);
            format!("{:016x}", crc.checksum(input))
        }
    }
}

fn parse_hex_key(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();

    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    if !cleaned.len().is_multiple_of(2) {
        return Err(anyhow!("Hex key length must be even"));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).map_err(|e| anyhow!("Invalid key bytes: {e}"))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| anyhow!("Invalid hex pair '{pair}' in key"))?;
        out.push(byte);
    }

    Ok(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod test {
    use super::{crc_digest, hmac_digest};
    use crate::commands::{CrcAlgorithm, HmacAlgorithm};

    #[test]
    fn hmac_sha256_vector() {
        let digest = hmac_digest(
            b"The quick brown fox jumps over the lazy dog",
            "key",
            false,
            HmacAlgorithm::Sha256,
        )
        .unwrap();
        assert_eq!(
            digest,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn hmac_sha512_vector() {
        let digest = hmac_digest(b"abc", "6b6579", true, HmacAlgorithm::Sha512).unwrap();
        assert_eq!(
            digest,
            "3926a207c8c42b0c41792cbd3e1a1aaaf5f7a25704f62dfc939c4987dd7ce060009c5bb1c2447355b3216f10b537e9afa7b64a4e5391b0d631172d07939e087a"
        );
    }

    #[test]
    fn crc32_vector() {
        assert_eq!(crc_digest(b"123456789", CrcAlgorithm::Crc32), "cbf43926");
    }

    #[test]
    fn crc64_vector() {
        assert_eq!(
            crc_digest(b"123456789", CrcAlgorithm::Crc64),
            "6c40df5f0b497347"
        );
    }
}
