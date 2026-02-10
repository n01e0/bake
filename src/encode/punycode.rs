use anyhow::{anyhow, Result};

pub fn encode(input: &str) -> Result<String> {
    idna::domain_to_ascii(input).map_err(|e| anyhow!("Can't encode punycode: {e}"))
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn punycode_encode() {
        assert_eq!(
            encode("ドメイン.テスト").unwrap(),
            "xn--eckwd4c7c.xn--zckzah"
        );
    }
}
