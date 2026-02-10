pub fn encode(input: &[u8], binary: bool) -> String {
    if binary {
        quoted_printable::encode_binary_to_str(input)
    } else {
        quoted_printable::encode_to_str(input)
    }
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn quoted_printable_encode() {
        assert_eq!(encode(b"hello=world", false), "hello=3Dworld");
    }
}
