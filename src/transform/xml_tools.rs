use anyhow::{anyhow, Result};
use sxd_document::parser;
use sxd_xpath::{Context, Factory, Value};
use xmltree::{Element, EmitterConfig};

pub fn pretty(input: &str) -> Result<String> {
    let element = Element::parse(input.as_bytes()).map_err(|e| anyhow!("Invalid XML: {e}"))?;
    let mut out = Vec::new();
    element
        .write_with_config(
            &mut out,
            EmitterConfig::new()
                .perform_indent(true)
                .write_document_declaration(false),
        )
        .map_err(|e| anyhow!("XML format error: {e}"))?;
    String::from_utf8(out).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

pub fn minify(input: &str) -> Result<String> {
    let element = Element::parse(input.as_bytes()).map_err(|e| anyhow!("Invalid XML: {e}"))?;
    let mut out = Vec::new();
    element
        .write_with_config(
            &mut out,
            EmitterConfig::new()
                .perform_indent(false)
                .write_document_declaration(false),
        )
        .map_err(|e| anyhow!("XML format error: {e}"))?;
    String::from_utf8(out).map_err(|e| anyhow!("UTF-8 conversion error: {e}"))
}

pub fn xpath(input: &str, query: &str) -> Result<String> {
    let package = parser::parse(input).map_err(|e| anyhow!("Invalid XML: {e}"))?;
    let document = package.as_document();

    let factory = Factory::new();
    let xpath = factory
        .build(query)
        .map_err(|e| anyhow!("Invalid XPath: {e}"))?
        .ok_or_else(|| anyhow!("Empty XPath expression"))?;

    let context = Context::new();
    let value = xpath
        .evaluate(&context, document.root())
        .map_err(|e| anyhow!("XPath evaluation error: {e}"))?;

    Ok(match value {
        Value::Nodeset(nodes) => nodes
            .document_order()
            .iter()
            .map(|n| n.string_value())
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.string(),
    })
}

#[cfg(test)]
mod test {
    use super::{minify, pretty, xpath};

    #[test]
    fn pretty_xml() {
        let out = pretty("<root><a>1</a><b>2</b></root>").unwrap();
        assert!(out.contains("\n"));
    }

    #[test]
    fn minify_xml() {
        let out = minify("<root>\n  <a>1</a>\n</root>").unwrap();
        assert_eq!(out, "<root><a>1</a></root>");
    }

    #[test]
    fn xpath_query() {
        let out = xpath("<root><a>1</a><a>2</a></root>", "//a/text()").unwrap();
        assert_eq!(out, "1\n2");
    }
}
