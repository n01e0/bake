use anyhow::{anyhow, Result};
use serde_json::{Map, Value};

pub fn json_to_yaml(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| anyhow!("Invalid JSON: {e}"))?;
    serde_yaml::to_string(&value).map_err(|e| anyhow!("YAML conversion error: {e}"))
}

pub fn yaml_to_json(input: &str, pretty: bool) -> Result<String> {
    let value: Value = serde_yaml::from_str(input).map_err(|e| anyhow!("Invalid YAML: {e}"))?;
    if pretty {
        serde_json::to_string_pretty(&value).map_err(|e| anyhow!("JSON format error: {e}"))
    } else {
        serde_json::to_string(&value).map_err(|e| anyhow!("JSON format error: {e}"))
    }
}

pub fn json_to_toml(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| anyhow!("Invalid JSON: {e}"))?;
    toml::to_string_pretty(&value).map_err(|e| anyhow!("TOML conversion error: {e}"))
}

pub fn toml_to_json(input: &str, pretty: bool) -> Result<String> {
    let value: toml::Value = toml::from_str(input).map_err(|e| anyhow!("Invalid TOML: {e}"))?;
    let json_value =
        serde_json::to_value(value).map_err(|e| anyhow!("JSON conversion error: {e}"))?;
    if pretty {
        serde_json::to_string_pretty(&json_value).map_err(|e| anyhow!("JSON format error: {e}"))
    } else {
        serde_json::to_string(&json_value).map_err(|e| anyhow!("JSON format error: {e}"))
    }
}

pub fn csv_to_json(input: &str, pretty: bool) -> Result<String> {
    let mut rdr = csv::Reader::from_reader(input.as_bytes());
    let headers = rdr
        .headers()
        .map_err(|e| anyhow!("CSV parse error: {e}"))?
        .clone();

    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| anyhow!("CSV parse error: {e}"))?;
        let mut obj = Map::new();
        for (h, v) in headers.iter().zip(rec.iter()) {
            obj.insert(h.to_string(), Value::String(v.to_string()));
        }
        rows.push(Value::Object(obj));
    }

    if pretty {
        serde_json::to_string_pretty(&Value::Array(rows))
            .map_err(|e| anyhow!("JSON format error: {e}"))
    } else {
        serde_json::to_string(&Value::Array(rows)).map_err(|e| anyhow!("JSON format error: {e}"))
    }
}

pub fn json_to_csv(input: &str) -> Result<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| anyhow!("Invalid JSON: {e}"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| anyhow!("JSON must be an array of objects"))?;

    let mut headers: Vec<String> = Vec::new();
    for row in rows {
        let obj = row
            .as_object()
            .ok_or_else(|| anyhow!("JSON array must contain objects"))?;
        for key in obj.keys() {
            if !headers.contains(key) {
                headers.push(key.clone());
            }
        }
    }

    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(&headers)
        .map_err(|e| anyhow!("CSV write error: {e}"))?;

    for row in rows {
        let obj = row.as_object().unwrap();
        let record: Vec<String> = headers
            .iter()
            .map(|h| obj.get(h).map(value_to_string).unwrap_or_default())
            .collect();
        wtr.write_record(record)
            .map_err(|e| anyhow!("CSV write error: {e}"))?;
    }

    let bytes = wtr
        .into_inner()
        .map_err(|e| anyhow!("CSV write error: {e}"))?;
    String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

pub fn url_parse(input: &str) -> Result<String> {
    let url = url::Url::parse(input.trim()).map_err(|e| anyhow!("Invalid URL: {e}"))?;
    let mut out = vec![
        format!("scheme={}", url.scheme()),
        format!("host={}", url.host_str().unwrap_or("")),
        format!(
            "port={}",
            url.port_or_known_default()
                .map(|p| p.to_string())
                .unwrap_or_default()
        ),
        format!("path={}", url.path()),
        format!("query={}", url.query().unwrap_or("")),
        format!("fragment={}", url.fragment().unwrap_or("")),
    ];

    for (k, v) in url.query_pairs() {
        out.push(format!("query_param:{}={}", k, v));
    }

    Ok(out.join("\n"))
}

pub fn url_normalize(input: &str) -> Result<String> {
    let mut url = url::Url::parse(input.trim()).map_err(|e| anyhow!("Invalid URL: {e}"))?;
    url.set_fragment(None);
    Ok(url.to_string())
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn yaml_json_roundtrip() {
        let yaml = json_to_yaml("{\"a\":1}").unwrap();
        assert!(yaml.contains("a: 1"));
        let json = yaml_to_json(&yaml, false).unwrap();
        assert_eq!(json, "{\"a\":1}");
    }

    #[test]
    fn toml_json_roundtrip() {
        let toml = json_to_toml("{\"a\":1}").unwrap();
        assert!(toml.contains("a = 1"));
        let json = toml_to_json("a = 1", false).unwrap();
        assert_eq!(json, "{\"a\":1}");
    }

    #[test]
    fn csv_json_roundtrip() {
        let json = csv_to_json("a,b\n1,2\n", false).unwrap();
        assert_eq!(json, "[{\"a\":\"1\",\"b\":\"2\"}]");
        let csv = json_to_csv(&json).unwrap();
        assert!(csv.contains("a,b"));
    }

    #[test]
    fn parse_url() {
        let out = url_parse("https://example.com:443/path?a=1#frag").unwrap();
        assert!(out.contains("scheme=https"));
        assert!(out.contains("query_param:a=1"));
    }
}
