use percent_encoding_rfc3986::{utf8_percent_encode, NON_ALPHANUMERIC};

pub fn encode(input: &str, all: bool) -> String {
    if all {
        input
            .as_bytes()
            .iter()
            .map(|byte| format!("%{:02X}", byte))
            .collect()
    } else {
        utf8_percent_encode(input, NON_ALPHANUMERIC).to_string()
    }
}
