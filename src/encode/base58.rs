pub fn encode(input: &[u8]) -> String {
    bs58::encode(input).into_string()
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn base58_encode() {
        assert_eq!(encode(b"hello"), "Cn8eVZg");
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b""), "");
    }
}
