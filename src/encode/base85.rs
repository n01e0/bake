pub fn encode(input: &[u8]) -> String {
    ascii85::encode(input)
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn base85_encode() {
        assert_eq!(encode(b"hello"), "<~BOu!rDZ~>");
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b""), "<~~>");
    }
}
