use crate::commands::CaseStyle;

#[derive(Debug, Clone)]
pub struct CaesarCandidate {
    pub shift: u8,
    pub score: f64,
    pub plaintext: String,
}

pub fn rot13(input: &str) -> String {
    caesar_with_shift(input, 13)
}

pub fn caesar(input: &str, shift: i8, decode: bool) -> String {
    let effective = if decode { -shift } else { shift };
    caesar_with_shift(input, effective)
}

pub fn rot13_bruteforce(
    input: &str,
    top: usize,
    min_score: f64,
    prefix: Option<&str>,
) -> Vec<CaesarCandidate> {
    if input.is_empty() || top == 0 {
        return Vec::new();
    }

    let mut candidates: Vec<CaesarCandidate> = (0u8..=25)
        .map(|shift| {
            let plaintext = caesar(input, shift as i8, true);
            let score = english_score(plaintext.as_bytes());
            CaesarCandidate {
                shift,
                score,
                plaintext,
            }
        })
        .filter(|c| c.score >= min_score)
        .filter(|c| prefix.map(|p| c.plaintext.starts_with(p)).unwrap_or(true))
        .collect();

    candidates.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.shift.cmp(&b.shift))
    });
    candidates.truncate(top);
    candidates
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

fn english_score(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut score = 0.0;
    for &b in bytes {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' => score += 2.0,
            b' ' => score += 3.0,
            b'0'..=b'9' => score += 0.7,
            b'.' | b',' | b'!' | b'?' | b'\'' | b'"' | b';' | b':' | b'-' | b'(' | b')' => {
                score += 0.4
            }
            b'\n' | b'\r' | b'\t' => score += 0.2,
            0x21..=0x7e => score += 0.1,
            _ => score -= 5.0,
        }
    }

    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for common in [" the ", " and ", " to ", " of ", " in "] {
        if lower.contains(common) {
            score += 8.0;
        }
    }

    let mut dictionary_hits = 0usize;
    for word in lower
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
    {
        if matches!(
            word,
            "the"
                | "and"
                | "that"
                | "have"
                | "for"
                | "not"
                | "with"
                | "you"
                | "this"
                | "but"
                | "his"
                | "from"
                | "they"
                | "say"
                | "her"
                | "she"
                | "will"
                | "one"
                | "all"
                | "would"
                | "there"
                | "their"
                | "what"
                | "about"
                | "which"
                | "when"
                | "make"
                | "can"
                | "like"
                | "time"
                | "just"
                | "know"
                | "take"
                | "people"
                | "into"
                | "year"
                | "good"
                | "some"
                | "could"
                | "them"
                | "see"
                | "other"
                | "than"
                | "then"
                | "now"
                | "look"
                | "only"
                | "come"
                | "its"
                | "over"
                | "think"
                | "also"
                | "back"
                | "after"
                | "use"
                | "two"
                | "how"
                | "our"
                | "work"
                | "first"
                | "well"
                | "way"
                | "even"
                | "new"
                | "want"
                | "because"
                | "any"
                | "these"
                | "give"
                | "day"
                | "most"
                | "us"
                | "hello"
                | "world"
        ) {
            dictionary_hits += 1;
        }
    }
    score += dictionary_hits as f64 * 4.0;

    score / bytes.len() as f64
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
    use super::{caesar, case_convert, rot13, rot13_bruteforce};
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
    fn rot13_bruteforce_contains_shift_13() {
        let results = rot13_bruteforce("uryyb jbeyq", 26, 0.0, None);
        assert!(results
            .iter()
            .any(|c| c.shift == 13 && c.plaintext == "hello world"));
    }

    #[test]
    fn rot13_bruteforce_prefix_filter() {
        let results = rot13_bruteforce("uryyb jbeyq", 26, 0.0, Some("hello"));
        assert!(!results.is_empty());
        assert!(results.iter().all(|c| c.plaintext.starts_with("hello")));
        assert!(results
            .iter()
            .any(|c| c.shift == 13 && c.plaintext == "hello world"));
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
