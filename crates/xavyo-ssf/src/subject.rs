//! Subject Identifiers (RFC 9493 + SSF §3.5).
//!
//! Identifies the subject of a Security Event Token via the top-level `sub_id`
//! claim. v1 supports the two formats xavyo needs to emit CAEP events about a
//! user: `iss_sub` (issuer + subject) and `email`. The tagged `format` member
//! drives serialization per RFC 9493 §3.

use serde::{Deserialize, Serialize};

/// An RFC 9493 Subject Identifier (the `sub_id` value of an SSF SET).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum SubjectId {
    /// `iss_sub` (RFC 9493 §3.2.1): issuer + subject pair.
    #[serde(rename = "iss_sub")]
    IssSub {
        /// The issuer of the subject (typically xavyo's issuer).
        iss: String,
        /// The subject identifier within that issuer (the user id).
        sub: String,
    },
    /// `email` (RFC 9493 §3.2.2).
    #[serde(rename = "email")]
    Email {
        /// The subject's email address.
        email: String,
    },
}

impl SubjectId {
    /// Construct an `iss_sub` subject identifier.
    pub fn iss_sub(iss: impl Into<String>, sub: impl Into<String>) -> Self {
        SubjectId::IssSub {
            iss: iss.into(),
            sub: sub.into(),
        }
    }

    /// Construct an `email` subject identifier.
    pub fn email(email: impl Into<String>) -> Self {
        SubjectId::Email {
            email: email.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn iss_sub_serializes_with_format_tag() {
        let s = SubjectId::iss_sub("https://idp.example.com", "user-42");
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({"format": "iss_sub", "iss": "https://idp.example.com", "sub": "user-42"})
        );
    }

    #[test]
    fn email_serializes_with_format_tag() {
        let s = SubjectId::email("a@b.com");
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({"format": "email", "email": "a@b.com"})
        );
    }

    #[test]
    fn roundtrips() {
        let s = SubjectId::iss_sub("iss", "sub");
        let v = serde_json::to_value(&s).unwrap();
        let back: SubjectId = serde_json::from_value(v).unwrap();
        assert_eq!(s, back);
    }
}
