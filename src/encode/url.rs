use percent_encoding_rfc3986::{utf8_percent_encode, NON_ALPHANUMERIC};

pub fn encode(arg: &str, all: bool) -> String {
    let ascii_set = NON_ALPHANUMERIC;
    if all {
        for c in 1..=128 {
            ascii_set.add(c);
        }
    }

    utf8_percent_encode(arg, ascii_set).to_string()
}
