use anyhow::{anyhow, Result};
use regex::RegexBuilder;

pub fn replace(
    input: &str,
    pattern: &str,
    replacement: &str,
    global: bool,
    multiline: bool,
    dotall: bool,
) -> Result<String> {
    let regex = RegexBuilder::new(pattern)
        .multi_line(multiline)
        .dot_matches_new_line(dotall)
        .build()
        .map_err(|e| anyhow!("Invalid regex pattern: {e}"))?;

    if global {
        Ok(regex.replace_all(input, replacement).to_string())
    } else {
        Ok(regex.replace(input, replacement).to_string())
    }
}

#[cfg(test)]
mod test {
    use super::replace;

    #[test]
    fn replaces_first_match_by_default() {
        let output = replace("foo foo", "foo", "bar", false, false, false).unwrap();
        assert_eq!(output, "bar foo");
    }

    #[test]
    fn replaces_all_matches_with_global_flag() {
        let output = replace("foo foo", "foo", "bar", true, false, false).unwrap();
        assert_eq!(output, "bar bar");
    }

    #[test]
    fn supports_capture_groups() {
        let output = replace("abc123", "([a-z]+)(\\d+)", "$2-$1", true, false, false).unwrap();
        assert_eq!(output, "123-abc");
    }

    #[test]
    fn multiline_mode() {
        let input = "alpha\nbeta\nalpha";
        let output = replace(input, "^alpha$", "A", true, true, false).unwrap();
        assert_eq!(output, "A\nbeta\nA");
    }

    #[test]
    fn dotall_mode() {
        let input = "a\nZ";
        let output = replace(input, "a.Z", "ok", false, false, true).unwrap();
        assert_eq!(output, "ok");
    }

    #[test]
    fn invalid_pattern() {
        let err = replace("text", "(", "x", false, false, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid regex pattern"));
    }
}
