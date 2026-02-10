pub fn encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());

    for ch in input.chars() {
        match ch {
            '&' => encoded.push_str("&amp;"),
            '<' => encoded.push_str("&lt;"),
            '>' => encoded.push_str("&gt;"),
            '"' => encoded.push_str("&quot;"),
            '\'' => encoded.push_str("&#39;"),
            _ => encoded.push(ch),
        }
    }

    encoded
}

#[cfg(test)]
mod test {
    use super::encode;

    #[test]
    fn escapes_reserved_chars() {
        assert_eq!(
            encode("<tag a='x' b=\"y\">&</tag>"),
            "&lt;tag a=&#39;x&#39; b=&quot;y&quot;&gt;&amp;&lt;/tag&gt;"
        );
    }

    #[test]
    fn keeps_unicode() {
        assert_eq!(encode("こんにちは & <3"), "こんにちは &amp; &lt;3");
    }
}
