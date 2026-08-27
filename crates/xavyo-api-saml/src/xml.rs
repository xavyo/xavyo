//! quick-xml 0.41+ helpers shared across SAML parsers.

use std::borrow::Cow;

use quick_xml::events::attributes::Attribute;
use quick_xml::events::BytesText;
use quick_xml::XmlVersion;

/// Decode a normalized attribute value for SAML 1.0-compatible documents.
/// Invalid encoding must not become an empty string.
pub fn attribute_value<'a>(attr: &'a Attribute<'_>) -> Result<Cow<'a, str>, String> {
    attr.normalized_value(XmlVersion::Implicit1_0)
        .map_err(|err| format!("invalid XML attribute encoding: {err}"))
}

/// Decode an XML local name or attribute key. Invalid encoding must not become empty.
pub fn decode_xml_name(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|err| format!("invalid XML name encoding: {err}"))
}

/// Decode XML text. Invalid encoding must not become an empty string.
pub fn decode_xml_text(e: &BytesText<'_>) -> Result<String, String> {
    e.decode()
        .map(|c| c.into_owned())
        .map_err(|err| format!("invalid XML text encoding: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    #[test]
    fn decode_xml_text_does_not_default_to_empty() {
        let mut reader = Reader::from_str("<a>hello</a>");
        reader.config_mut().trim_text(true);
        loop {
            match reader.read_event().unwrap() {
                Event::Text(e) => {
                    assert_eq!(decode_xml_text(&e).unwrap(), "hello");
                    break;
                }
                Event::Eof => panic!("missing text"),
                _ => {}
            }
        }
        let src = include_str!("xml.rs");
        let production = src.split("mod tests").next().expect("production source");
        let decode = production
            .split("fn decode_xml_text")
            .nth(1)
            .expect("decode_xml_text");
        assert!(
            !decode.contains("unwrap_or_default()"),
            "XML text decode must not become empty on error"
        );
    }

    #[test]
    fn attribute_value_does_not_default_to_empty() {
        let src = include_str!("xml.rs");
        let production = src.split("mod tests").next().expect("production source");
        let attr_fn = production
            .split("fn attribute_value")
            .nth(1)
            .expect("attribute_value");
        assert!(
            !attr_fn.contains("unwrap_or_default()"),
            "XML attribute decode must not become empty on error"
        );
    }

    #[test]
    fn decode_xml_name_does_not_default_to_empty() {
        assert_eq!(decode_xml_name(b"Issuer").unwrap(), "Issuer");
        assert!(decode_xml_name(&[0xff, 0xfe]).is_err());
        let src = include_str!("xml.rs");
        let production = src.split("mod tests").next().expect("production source");
        let name_fn = production
            .split("fn decode_xml_name")
            .nth(1)
            .expect("decode_xml_name");
        assert!(
            !name_fn.contains("unwrap_or(\"\")") && !name_fn.contains("from_utf8_lossy"),
            "XML name decode must not become empty on error"
        );
    }
}
