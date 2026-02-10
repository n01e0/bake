use anyhow::{anyhow, Result};
use serde_json::Value;

pub fn pretty(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| anyhow!("Invalid JSON: {e}"))?;
    serde_json::to_string_pretty(&value).map_err(|e| anyhow!("JSON format error: {e}"))
}

pub fn minify(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| anyhow!("Invalid JSON: {e}"))?;
    serde_json::to_string(&value).map_err(|e| anyhow!("JSON format error: {e}"))
}

pub fn query(input: &str, query: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| anyhow!("Invalid JSON: {e}"))?;
    let selected =
        jsonpath_lib::select(&value, query).map_err(|e| anyhow!("Invalid JSONPath: {e}"))?;

    let lines = selected
        .iter()
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "null".to_string()))
        .collect::<Vec<_>>();
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod test {
    use super::{minify, pretty, query};

    #[test]
    fn pretty_json() {
        let out = pretty("{\"a\":1,\"b\":[2,3]}").unwrap();
        assert!(out.contains("\n"));
        assert!(out.contains("\"a\": 1"));
    }

    #[test]
    fn minify_json() {
        assert_eq!(minify("{\n  \"a\": 1\n}").unwrap(), "{\"a\":1}");
    }

    #[test]
    fn query_jsonpath() {
        let out = query("{\"items\":[{\"id\":1},{\"id\":2}]}", "$.items[*].id").unwrap();
        assert_eq!(out, "1\n2");
    }
}
