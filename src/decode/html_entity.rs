pub fn decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '&' {
            out.push(ch);
            continue;
        }

        let mut entity = String::new();
        let mut found_semicolon = false;

        while let Some(&next) = chars.peek() {
            chars.next();
            if next == ';' {
                found_semicolon = true;
                break;
            }
            entity.push(next);
            if entity.len() > 32 {
                break;
            }
        }

        if !found_semicolon {
            out.push('&');
            out.push_str(&entity);
            continue;
        }

        match decode_entity(&entity) {
            Some(decoded) => out.push(decoded),
            None => {
                out.push('&');
                out.push_str(&entity);
                out.push(';');
            }
        }
    }

    out
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "#39" => Some('\''),
        _ => decode_numeric_entity(entity),
    }
}

fn decode_numeric_entity(entity: &str) -> Option<char> {
    if let Some(num) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        u32::from_str_radix(num, 16).ok().and_then(char::from_u32)
    } else if let Some(num) = entity.strip_prefix('#') {
        num.parse::<u32>().ok().and_then(char::from_u32)
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::decode;

    #[test]
    fn decodes_named_entities() {
        assert_eq!(decode("&lt;&gt;&amp;&quot;&apos;&#39;"), "<>&\"''");
    }

    #[test]
    fn decodes_numeric_entities() {
        assert_eq!(decode("&#65;&#x42;"), "AB");
    }

    #[test]
    fn leaves_invalid_entities_untouched() {
        assert_eq!(decode("&notanentity; &foo"), "&notanentity; &foo");
    }

    #[test]
    fn mixed_content() {
        assert_eq!(decode("hello &lt;world&gt;"), "hello <world>");
    }
}
