pub fn encode(input: &str) -> String {
    input
        .encode_utf16()
        .map(|u| format!("\\u{u:04X}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn unicode_escape_encode() {
        assert_eq!(encode("Aあ"), "\\u0041\\u3042");
    }
}
