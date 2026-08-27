//! quick-xml 0.41+ helpers shared across SAML parsers.

use std::borrow::Cow;

use quick_xml::events::attributes::Attribute;
use quick_xml::XmlVersion;

/// Decode a normalized attribute value for SAML 1.0-compatible documents.
pub fn attribute_value<'a>(attr: &'a Attribute<'_>) -> Cow<'a, str> {
    attr.normalized_value(XmlVersion::Implicit1_0)
        .unwrap_or_default()
}
