use anyhow::{anyhow, Result};

pub fn decode(input: &str) -> Result<String> {
    let (decoded, status) = idna::domain_to_unicode(input);
    status.map_err(|e| anyhow!("Can't decode punycode: {e}"))?;
    Ok(decoded)
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn punycode_decode() {
        assert_eq!(
            decode("xn--eckwd4c7c.xn--zckzah").unwrap(),
            "ドメイン.テスト"
        );
    }
}
