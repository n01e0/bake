pub fn encode(input: &[u8]) -> String {
    String::from_utf8_lossy(&base91::slice_encode(input)).to_string()
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn base91_encode() {
        assert_eq!(encode(b"hello"), "TPwJh>A");
    }
}
