use crate::commands::CaseStyle;

pub fn rot13(input: &str) -> String {
    caesar_with_shift(input, 13)
}

pub fn caesar(input: &str, shift: i8, decode: bool) -> String {
    let effective = if decode { -shift } else { shift };
    caesar_with_shift(input, effective)
}

pub fn case_convert(input: &str, style: CaseStyle) -> String {
    let words = split_words(input);
    match style {
        CaseStyle::Lower => words.join(" ").to_lowercase(),
        CaseStyle::Upper => words.join(" ").to_uppercase(),
        CaseStyle::Snake => words.join("_").to_lowercase(),
        CaseStyle::Kebab => words.join("-").to_lowercase(),
        CaseStyle::Camel => {
            let mut out = String::new();
            for (i, w) in words.iter().enumerate() {
                if i == 0 {
                    out.push_str(&w.to_lowercase());
                } else {
                    out.push_str(&capitalize(w));
                }
            }
            out
        }
        CaseStyle::Pascal => words.iter().map(|w| capitalize(w)).collect::<String>(),
    }
}

fn caesar_with_shift(input: &str, shift: i8) -> String {
    input
        .chars()
        .map(|c| shift_char(c, shift))
        .collect::<String>()
}

fn shift_char(c: char, shift: i8) -> char {
    let (start, end) = if c.is_ascii_lowercase() {
        (b'a', b'z')
    } else if c.is_ascii_uppercase() {
        (b'A', b'Z')
    } else {
        return c;
    };

    let alpha_len = (end - start + 1) as i16;
    let pos = c as i16 - start as i16;
    let shifted = (pos + shift as i16).rem_euclid(alpha_len);
    (start + shifted as u8) as char
}

fn split_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase()
                && !current.is_empty()
                && current.chars().last().unwrap().is_ascii_lowercase()
            {
                words.push(current.clone());
                current.clear();
            }
            current.push(ch);
        } else if !current.is_empty() {
            words.push(current.clone());
            current.clear();
        }
    }

    if !current.is_empty() {
        words.push(current);
    }

    if words.is_empty() {
        vec![String::new()]
    } else {
        words
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => {
            first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
        }
        None => String::new(),
    }
}

#[cfg(test)]
mod test {
    use super::{caesar, case_convert, rot13};
    use crate::commands::CaseStyle;

    #[test]
    fn rot13_roundtrip() {
        assert_eq!(rot13("uryyb"), "hello");
    }

    #[test]
    fn caesar_encode_decode() {
        let encoded = caesar("abc", 3, false);
        assert_eq!(encoded, "def");
        assert_eq!(caesar(&encoded, 3, true), "abc");
    }

    #[test]
    fn case_styles() {
        assert_eq!(
            case_convert("hello_world-test", CaseStyle::Camel),
            "helloWorldTest"
        );
        assert_eq!(
            case_convert("helloWorldTest", CaseStyle::Snake),
            "hello_world_test"
        );
    }
}
