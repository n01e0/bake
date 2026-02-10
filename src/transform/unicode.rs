use crate::commands::UnicodeForm;
use unicode_normalization::UnicodeNormalization;

pub fn normalize(input: &str, form: UnicodeForm) -> String {
    match form {
        UnicodeForm::Nfc => input.nfc().collect(),
        UnicodeForm::Nfd => input.nfd().collect(),
        UnicodeForm::Nfkc => input.nfkc().collect(),
        UnicodeForm::Nfkd => input.nfkd().collect(),
    }
}

#[cfg(test)]
mod test {
    use super::normalize;
    use crate::commands::UnicodeForm;

    #[test]
    fn nfc_composes() {
        let input = "e\u{301}";
        assert_eq!(normalize(input, UnicodeForm::Nfc), "é");
    }

    #[test]
    fn nfd_decomposes() {
        let input = "é";
        assert_eq!(normalize(input, UnicodeForm::Nfd), "e\u{301}");
    }

    #[test]
    fn nfkc_compatibility() {
        let input = "①";
        assert_eq!(normalize(input, UnicodeForm::Nfkc), "1");
    }

    #[test]
    fn nfkd_compatibility_decompose() {
        let input = "①";
        assert_eq!(normalize(input, UnicodeForm::Nfkd), "1");
    }

    #[test]
    fn keeps_plain_ascii() {
        assert_eq!(normalize("hello", UnicodeForm::Nfc), "hello");
    }
}
