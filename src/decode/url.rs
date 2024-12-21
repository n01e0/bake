use anyhow::{anyhow, Result};
use percent_encoding_rfc3986::percent_decode_str;

pub fn decode(arg: &str) -> Result<String> {
    Ok(percent_decode_str(arg)
        .map_err(|e| anyhow!("Can't decode url: {:?}", e))?
        .decode_utf8()?
        .to_string())
}
