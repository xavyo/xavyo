use uuid::Uuid;
use xavyo_core::TenantId;

use crate::error::ExtAuthzError;
use crate::proto;

/// Parsed authorization context extracted from a CheckRequest.
#[derive(Debug, Clone)]
pub struct AuthzContext {
    /// Subject (agent/NHI) ID from JWT `sub` claim.
    pub subject_id: Uuid,

    /// Tenant ID from JWT `tid` claim (type-safe).
    pub tenant_id: TenantId,

    /// Roles from JWT `roles` claim.
    pub roles: Vec<String>,

    /// HTTP method (GET, POST, etc.).
    pub method: String,

    /// Request path.
    pub path: String,

    /// Derived action from HTTP method.
    pub action: String,

    /// Derived resource type from path.
    pub resource_type: String,

    /// Whether the JWT was extracted from trusted `metadata_context`
    /// (set by upstream JWT authn filter with signature verification)
    /// vs the Authorization header fallback (base64 decode only, no verification).
    pub from_metadata_context: bool,

    /// RFC 8693 actor claim (if delegated token).
    pub act: Option<xavyo_auth::ActorClaim>,

    /// Delegation grant ID (if delegated token).
    pub delegation_id: Option<Uuid>,

    /// Delegation depth (if delegated token).
    pub delegation_depth: Option<i32>,
}

/// Extract authorization context from a CheckRequest.
pub fn parse_check_request(request: &proto::CheckRequest) -> Result<AuthzContext, ExtAuthzError> {
    let attributes = request
        .attributes
        .as_ref()
        .ok_or(ExtAuthzError::MissingAttributes)?;

    let http = attributes
        .request
        .as_ref()
        .and_then(|r| r.http.as_ref())
        .ok_or(ExtAuthzError::MissingHttpRequest)?;

    let method = http.method.clone();
    let path = http.path.clone();

    // Extract JWT claims: try metadata_context first, then Authorization header
    let claims = extract_jwt_claims(attributes, http)?;

    let subject_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|e| ExtAuthzError::InvalidSubjectId(e.to_string()))?;

    let tenant_id = claims
        .tid
        .parse::<TenantId>()
        .map_err(|e| ExtAuthzError::InvalidTenantId(e.to_string()))?;

    let action = derive_action(&method);
    let resource_type = derive_resource_type(&path);

    // Parse act claim for delegation and validate chain depth
    let act = claims
        .act
        .and_then(|v| serde_json::from_value::<xavyo_auth::ActorClaim>(v).ok())
        .and_then(|a| match a.validate_depth() {
            Ok(()) => Some(a),
            Err(e) => {
                tracing::warn!("rejecting act claim: {e}");
                None
            }
        });
    let delegation_id = claims.delegation_id.and_then(|s| Uuid::parse_str(&s).ok());
    let delegation_depth = claims.delegation_depth;

    Ok(AuthzContext {
        subject_id,
        tenant_id,
        roles: claims.roles,
        method,
        path,
        action,
        resource_type,
        from_metadata_context: claims.from_metadata_context,
        act,
        delegation_id,
        delegation_depth,
    })
}

/// JWT claims we care about.
#[derive(Debug)]
struct JwtClaims {
    sub: String,
    tid: String,
    roles: Vec<String>,
    /// True if extracted from trusted metadata_context, false for header fallback.
    from_metadata_context: bool,
    // Delegation fields
    act: Option<serde_json::Value>,
    delegation_id: Option<String>,
    delegation_depth: Option<i32>,
}

/// Extract JWT claims from metadata_context or Authorization header.
fn extract_jwt_claims(
    attributes: &proto::AttributeContext,
    http: &proto::attribute_context::HttpRequest,
) -> Result<JwtClaims, ExtAuthzError> {
    // Try metadata_context first (set by JWT authn filter — signature already verified upstream)
    if let Some(metadata) = &attributes.metadata_context {
        if let Some(jwt_struct) = metadata.filter_metadata.get("envoy.filters.http.jwt_authn") {
            if let Some(payload) = jwt_struct.fields.get("jwt_payload") {
                if let Some(prost_types::value::Kind::StructValue(payload_struct)) = &payload.kind {
                    return extract_claims_from_struct(payload_struct);
                }
            }
        }
    }

    // Fallback: decode JWT from Authorization header (no signature verification!)
    if let Some(auth_header) = http.headers.get("authorization") {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            tracing::warn!(
                "JWT extracted from Authorization header fallback — \
                 signature NOT verified by ext_authz. \
                 Ensure upstream JWT authn filter is configured."
            );
            return decode_jwt_payload(token);
        }
    }

    Err(ExtAuthzError::JwtExtraction(
        "no JWT found in metadata_context or Authorization header".into(),
    ))
}

/// Extract claims from a protobuf Struct (jwt_payload from metadata_context).
fn extract_claims_from_struct(s: &prost_types::Struct) -> Result<JwtClaims, ExtAuthzError> {
    let sub = get_string_field(s, "sub")
        .ok_or_else(|| ExtAuthzError::JwtExtraction("missing 'sub' claim".into()))?;

    let tid = get_string_field(s, "tid")
        .ok_or_else(|| ExtAuthzError::JwtExtraction("missing 'tid' claim".into()))?;

    let roles = get_string_list_field(s, "roles").unwrap_or_default();

    // Delegation fields
    let act = get_struct_field_as_json(s, "act");
    let delegation_id = get_string_field(s, "delegation_id");
    let delegation_depth = get_number_field(s, "delegation_depth").map(|n| n as i32);

    Ok(JwtClaims {
        sub,
        tid,
        roles,
        from_metadata_context: true,
        act,
        delegation_id,
        delegation_depth,
    })
}

/// Decode the payload section of a JWT (base64url, no signature verification).
fn decode_jwt_payload(token: &str) -> Result<JwtClaims, ExtAuthzError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ExtAuthzError::JwtExtraction("invalid JWT format".into()));
    }

    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| ExtAuthzError::JwtExtraction(format!("base64 decode error: {e}")))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| ExtAuthzError::JwtExtraction(format!("JSON parse error: {e}")))?;

    let sub = payload["sub"]
        .as_str()
        .ok_or_else(|| ExtAuthzError::JwtExtraction("missing 'sub' in JWT payload".into()))?
        .to_string();

    let tid = payload["tid"]
        .as_str()
        .ok_or_else(|| ExtAuthzError::JwtExtraction("missing 'tid' in JWT payload".into()))?
        .to_string();

    let roles = payload["roles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Delegation fields
    let act = if payload["act"].is_object() {
        Some(payload["act"].clone())
    } else {
        None
    };
    let delegation_id = payload["delegation_id"].as_str().map(|s| s.to_string());
    let delegation_depth = payload["delegation_depth"].as_i64().map(|n| n as i32);

    Ok(JwtClaims {
        sub,
        tid,
        roles,
        from_metadata_context: false,
        act,
        delegation_id,
        delegation_depth,
    })
}

/// Derive an action string from the HTTP method.
fn derive_action(method: &str) -> String {
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" => "read".to_string(),
        "POST" => "create".to_string(),
        "PUT" | "PATCH" => "update".to_string(),
        "DELETE" => "delete".to_string(),
        other => other.to_lowercase(),
    }
}

/// Segments to skip when deriving the resource type from a path.
const SKIP_SEGMENTS: &[&str] = &["api"];

/// Derive a resource type from the request path.
///
/// Skips version prefixes (v1, v2), the "api" prefix, UUID segments,
/// and numeric IDs. Returns the first meaningful path segment.
fn derive_resource_type(path: &str) -> String {
    // Strip query string
    let path = path.split('?').next().unwrap_or(path);

    // Split into segments, skip empty and version prefixes (v1, v2, etc.)
    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .filter(|s| {
            !(s.starts_with('v') && s.len() <= 3 && s[1..].chars().all(|c| c.is_ascii_digit()))
        })
        .collect();

    // Find the first non-ID, non-skippable segment as resource type
    for seg in &segments {
        // Skip known prefixes
        if SKIP_SEGMENTS.contains(seg) {
            continue;
        }
        // Skip UUIDs
        if Uuid::parse_str(seg).is_ok() {
            continue;
        }
        // Skip purely numeric segments (e.g., "123")
        if seg.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        return seg.to_string();
    }

    "unknown".to_string()
}

/// Helper: get a string field from a protobuf Struct.
fn get_string_field(s: &prost_types::Struct, key: &str) -> Option<String> {
    s.fields.get(key).and_then(|v| {
        if let Some(prost_types::value::Kind::StringValue(s)) = &v.kind {
            Some(s.clone())
        } else {
            None
        }
    })
}

/// Helper: get a number field from a protobuf Struct.
fn get_number_field(s: &prost_types::Struct, key: &str) -> Option<f64> {
    s.fields.get(key).and_then(|v| {
        if let Some(prost_types::value::Kind::NumberValue(n)) = &v.kind {
            Some(*n)
        } else {
            None
        }
    })
}

/// Helper: convert a protobuf Struct field to a serde_json::Value (for nested structs like `act`).
fn get_struct_field_as_json(s: &prost_types::Struct, key: &str) -> Option<serde_json::Value> {
    s.fields.get(key).and_then(|v| {
        if let Some(prost_types::value::Kind::StructValue(inner)) = &v.kind {
            Some(prost_struct_to_json(inner))
        } else {
            None
        }
    })
}

/// Convert a prost_types::Struct to serde_json::Value.
fn prost_struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in &s.fields {
        if let Some(ref kind) = v.kind {
            let json_val = match kind {
                prost_types::value::Kind::StringValue(sv) => serde_json::Value::String(sv.clone()),
                prost_types::value::Kind::NumberValue(n) => {
                    serde_json::json!(*n)
                }
                prost_types::value::Kind::BoolValue(b) => serde_json::Value::Bool(*b),
                prost_types::value::Kind::NullValue(_) => serde_json::Value::Null,
                prost_types::value::Kind::StructValue(inner) => prost_struct_to_json(inner),
                prost_types::value::Kind::ListValue(list) => {
                    let items: Vec<serde_json::Value> = list
                        .values
                        .iter()
                        .filter_map(|item| {
                            item.kind.as_ref().map(|k| match k {
                                prost_types::value::Kind::StringValue(sv) => {
                                    serde_json::Value::String(sv.clone())
                                }
                                prost_types::value::Kind::NumberValue(n) => serde_json::json!(*n),
                                prost_types::value::Kind::BoolValue(b) => {
                                    serde_json::Value::Bool(*b)
                                }
                                prost_types::value::Kind::StructValue(inner) => {
                                    prost_struct_to_json(inner)
                                }
                                _ => serde_json::Value::Null,
                            })
                        })
                        .collect();
                    serde_json::Value::Array(items)
                }
            };
            map.insert(k.clone(), json_val);
        }
    }
    serde_json::Value::Object(map)
}

/// Helper: get a list of strings from a protobuf Struct field.
fn get_string_list_field(s: &prost_types::Struct, key: &str) -> Option<Vec<String>> {
    s.fields.get(key).and_then(|v| {
        if let Some(prost_types::value::Kind::ListValue(list)) = &v.kind {
            Some(
                list.values
                    .iter()
                    .filter_map(|v| {
                        if let Some(prost_types::value::Kind::StringValue(s)) = &v.kind {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
            )
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn test_derive_action() {
        assert_eq!(derive_action("GET"), "read");
        assert_eq!(derive_action("HEAD"), "read");
        assert_eq!(derive_action("OPTIONS"), "read");
        assert_eq!(derive_action("POST"), "create");
        assert_eq!(derive_action("PUT"), "update");
        assert_eq!(derive_action("PATCH"), "update");
        assert_eq!(derive_action("DELETE"), "delete");
        assert_eq!(derive_action("get"), "read");
        assert_eq!(derive_action("CUSTOM"), "custom");
    }

    #[test]
    fn test_derive_resource_type() {
        // Skips /api prefix
        assert_eq!(derive_resource_type("/api/v1/agents/123"), "agents");
        // Direct resource
        assert_eq!(derive_resource_type("/agents"), "agents");
        // Skips version prefix
        assert_eq!(
            derive_resource_type(&format!("/v1/agents/{}", Uuid::new_v4())),
            "agents"
        );
        // Empty path
        assert_eq!(derive_resource_type("/"), "unknown");
        // Skips both api and version
        assert_eq!(derive_resource_type("/api/v2/tools/list"), "tools");
        // Handles query string
        assert_eq!(derive_resource_type("/api/v1/agents?page=1"), "agents");
        // Handles numeric ID after resource
        assert_eq!(derive_resource_type("/v1/users/42/roles"), "users");
        // Just api prefix should return unknown
        assert_eq!(derive_resource_type("/api"), "unknown");
        // Handles multiple path segments
        assert_eq!(derive_resource_type("/api/v1/nhi/identities"), "nhi");
    }

    #[test]
    fn test_decode_jwt_payload() {
        use base64::Engine;

        let payload = serde_json::json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "tid": "660e8400-e29b-41d4-a716-446655440000",
            "roles": ["admin", "agent"]
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());

        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload_b64}.signature");
        let claims = decode_jwt_payload(&token).unwrap();

        assert_eq!(claims.sub, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(claims.tid, "660e8400-e29b-41d4-a716-446655440000");
        assert_eq!(claims.roles, vec!["admin", "agent"]);
    }

    #[test]
    fn test_decode_jwt_payload_invalid_format() {
        let result = decode_jwt_payload("not-a-jwt");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid JWT format"));
    }

    #[test]
    fn test_decode_jwt_payload_missing_sub() {
        use base64::Engine;

        let payload = serde_json::json!({"tid": "660e8400-e29b-41d4-a716-446655440000"});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("header.{payload_b64}.sig");

        let result = decode_jwt_payload(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sub"));
    }

    #[test]
    fn test_decode_jwt_payload_missing_tid() {
        use base64::Engine;

        let payload = serde_json::json!({"sub": "550e8400-e29b-41d4-a716-446655440000"});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("header.{payload_b64}.sig");

        let result = decode_jwt_payload(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tid"));
    }

    #[test]
    fn test_decode_jwt_payload_no_roles() {
        use base64::Engine;

        let payload = serde_json::json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "tid": "660e8400-e29b-41d4-a716-446655440000"
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("header.{payload_b64}.sig");

        let claims = decode_jwt_payload(&token).unwrap();
        assert!(claims.roles.is_empty());
    }

    #[test]
    fn test_extract_claims_from_struct() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "sub".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "550e8400-e29b-41d4-a716-446655440000".to_string(),
                )),
            },
        );
        fields.insert(
            "tid".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "660e8400-e29b-41d4-a716-446655440000".to_string(),
                )),
            },
        );
        fields.insert(
            "roles".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: vec![prost_types::Value {
                            kind: Some(prost_types::value::Kind::StringValue("admin".to_string())),
                        }],
                    },
                )),
            },
        );

        let s = prost_types::Struct { fields };
        let claims = extract_claims_from_struct(&s).unwrap();
        assert_eq!(claims.sub, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(claims.tid, "660e8400-e29b-41d4-a716-446655440000");
        assert_eq!(claims.roles, vec!["admin"]);
    }

    #[test]
    fn test_extract_claims_from_struct_missing_sub() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "tid".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("tid-val".to_string())),
            },
        );
        let s = prost_types::Struct { fields };
        assert!(extract_claims_from_struct(&s).is_err());
    }

    #[test]
    fn test_parse_check_request_missing_attributes() {
        let req = proto::CheckRequest { attributes: None };
        let result = parse_check_request(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtAuthzError::MissingAttributes
        ));
    }

    #[test]
    fn test_parse_check_request_missing_http() {
        let req = proto::CheckRequest {
            attributes: Some(proto::AttributeContext {
                source: None,
                destination: None,
                request: None,
                context_extensions: Default::default(),
                metadata_context: None,
                tls_session: None,
            }),
        };
        let result = parse_check_request(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtAuthzError::MissingHttpRequest
        ));
    }

    #[test]
    fn test_parse_check_request_no_jwt() {
        let req = proto::CheckRequest {
            attributes: Some(proto::AttributeContext {
                source: None,
                destination: None,
                request: Some(proto::attribute_context::Request {
                    time: None,
                    http: Some(proto::attribute_context::HttpRequest {
                        id: String::new(),
                        method: "GET".to_string(),
                        headers: Default::default(),
                        path: "/api/v1/agents".to_string(),
                        host: String::new(),
                        scheme: String::new(),
                        query: String::new(),
                        fragment: String::new(),
                        size: 0,
                        protocol: String::new(),
                        body: String::new(),
                        raw_body: vec![],
                    }),
                }),
                context_extensions: Default::default(),
                metadata_context: None,
                tls_session: None,
            }),
        };
        let result = parse_check_request(&req);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ExtAuthzError::JwtExtraction(_)
        ));
    }

    #[test]
    fn test_parse_check_request_with_bearer_token() {
        use base64::Engine;

        let payload = serde_json::json!({
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "tid": "660e8400-e29b-41d4-a716-446655440000",
            "roles": ["agent"]
        });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("Bearer eyJhbGciOiJSUzI1NiJ9.{payload_b64}.sig");

        let mut headers = std::collections::HashMap::new();
        headers.insert("authorization".to_string(), token);

        let req = proto::CheckRequest {
            attributes: Some(proto::AttributeContext {
                source: None,
                destination: None,
                request: Some(proto::attribute_context::Request {
                    time: None,
                    http: Some(proto::attribute_context::HttpRequest {
                        id: String::new(),
                        method: "POST".to_string(),
                        headers,
                        path: "/api/v1/agents".to_string(),
                        host: String::new(),
                        scheme: String::new(),
                        query: String::new(),
                        fragment: String::new(),
                        size: 0,
                        protocol: String::new(),
                        body: String::new(),
                        raw_body: vec![],
                    }),
                }),
                context_extensions: Default::default(),
                metadata_context: None,
                tls_session: None,
            }),
        };
        let ctx = parse_check_request(&req).unwrap();
        assert_eq!(
            ctx.subject_id.to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            ctx.tenant_id.to_string(),
            "660e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(ctx.roles, vec!["agent"]);
        assert_eq!(ctx.action, "create");
        assert_eq!(ctx.resource_type, "agents");
        // Bearer token fallback — not from metadata_context
        assert!(!ctx.from_metadata_context);
        // No delegation claims
        assert!(ctx.act.is_none());
        assert!(ctx.delegation_id.is_none());
        assert!(ctx.delegation_depth.is_none());
    }

    #[test]
    fn test_parse_check_request_with_metadata_context() {
        let mut jwt_fields = BTreeMap::new();
        jwt_fields.insert(
            "sub".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "550e8400-e29b-41d4-a716-446655440000".to_string(),
                )),
            },
        );
        jwt_fields.insert(
            "tid".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    "660e8400-e29b-41d4-a716-446655440000".to_string(),
                )),
            },
        );
        jwt_fields.insert(
            "roles".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: vec![prost_types::Value {
                            kind: Some(prost_types::value::Kind::StringValue("admin".to_string())),
                        }],
                    },
                )),
            },
        );

        let jwt_payload = prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: jwt_fields,
            })),
        };

        let mut jwt_authn_fields = BTreeMap::new();
        jwt_authn_fields.insert("jwt_payload".to_string(), jwt_payload);

        let mut filter_metadata = HashMap::new();
        filter_metadata.insert(
            "envoy.filters.http.jwt_authn".to_string(),
            prost_types::Struct {
                fields: jwt_authn_fields,
            },
        );

        // Build metadata_context with filter_metadata containing JWT claims
        let req = proto::CheckRequest {
            attributes: Some(proto::AttributeContext {
                source: None,
                destination: None,
                request: Some(proto::attribute_context::Request {
                    time: None,
                    http: Some(proto::attribute_context::HttpRequest {
                        id: String::new(),
                        method: "GET".to_string(),
                        headers: Default::default(),
                        path: "/v1/tools".to_string(),
                        host: String::new(),
                        scheme: String::new(),
                        query: String::new(),
                        fragment: String::new(),
                        size: 0,
                        protocol: String::new(),
                        body: String::new(),
                        raw_body: vec![],
                    }),
                }),
                context_extensions: Default::default(),
                metadata_context: Some(proto::Metadata { filter_metadata }),
                tls_session: None,
            }),
        };

        let ctx = parse_check_request(&req).unwrap();
        assert_eq!(
            ctx.subject_id.to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            ctx.tenant_id.to_string(),
            "660e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(ctx.roles, vec!["admin"]);
        assert_eq!(ctx.action, "read");
        assert_eq!(ctx.resource_type, "tools");
        // Extracted from metadata_context — trusted source
        assert!(ctx.from_metadata_context);
    }

    /// Helper: build a CheckRequest with a bearer token JWT containing the given payload.
    fn check_request_with_bearer(payload: &serde_json::Value) -> proto::CheckRequest {
        use base64::Engine;

        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        let token = format!("Bearer eyJhbGciOiJSUzI1NiJ9.{payload_b64}.sig");

        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), token);

        proto::CheckRequest {
            attributes: Some(proto::AttributeContext {
                source: None,
                destination: None,
                request: Some(proto::attribute_context::Request {
                    time: None,
                    http: Some(proto::attribute_context::HttpRequest {
                        id: String::new(),
                        method: "GET".to_string(),
                        headers,
                        path: "/api/v1/agents".to_string(),
                        host: String::new(),
                        scheme: String::new(),
                        query: String::new(),
                        fragment: String::new(),
                        size: 0,
                        protocol: String::new(),
                        body: String::new(),
                        raw_body: vec![],
                    }),
                }),
                context_extensions: Default::default(),
                metadata_context: None,
                tls_session: None,
            }),
        }
    }

    #[test]
    fn test_parse_delegated_token_from_bearer() {
        let subject_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let delegation_uuid = Uuid::new_v4();

        let payload = serde_json::json!({
            "sub": subject_id.to_string(),
            "tid": tenant_id.to_string(),
            "roles": ["agent"],
            "act": {"sub": actor_id.to_string(), "nhi_type": "agent"},
            "delegation_id": delegation_uuid.to_string(),
            "delegation_depth": 1
        });

        let req = check_request_with_bearer(&payload);
        let ctx = parse_check_request(&req).unwrap();

        assert_eq!(ctx.subject_id, subject_id);
        assert_eq!(ctx.tenant_id.to_string(), tenant_id.to_string());
        assert!(ctx.act.is_some());
        let act = ctx.act.unwrap();
        assert_eq!(act.sub, actor_id.to_string());
        assert_eq!(act.nhi_type, Some("agent".to_string()));
        assert_eq!(ctx.delegation_id, Some(delegation_uuid));
        assert_eq!(ctx.delegation_depth, Some(1));
    }

    #[test]
    fn test_parse_delegated_token_from_metadata_context() {
        let subject_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let delegation_uuid = Uuid::new_v4();

        let mut jwt_fields = BTreeMap::new();
        jwt_fields.insert(
            "sub".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    subject_id.to_string(),
                )),
            },
        );
        jwt_fields.insert(
            "tid".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(tenant_id.to_string())),
            },
        );
        jwt_fields.insert(
            "roles".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(
                    prost_types::ListValue {
                        values: vec![prost_types::Value {
                            kind: Some(prost_types::value::Kind::StringValue("agent".to_string())),
                        }],
                    },
                )),
            },
        );

        // Add act as a nested struct
        let mut act_fields = BTreeMap::new();
        act_fields.insert(
            "sub".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(actor_id.to_string())),
            },
        );
        act_fields.insert(
            "nhi_type".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue("agent".to_string())),
            },
        );
        jwt_fields.insert(
            "act".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                    fields: act_fields,
                })),
            },
        );

        // Add delegation_id as string
        jwt_fields.insert(
            "delegation_id".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StringValue(
                    delegation_uuid.to_string(),
                )),
            },
        );

        // Add delegation_depth as number
        jwt_fields.insert(
            "delegation_depth".to_string(),
            prost_types::Value {
                kind: Some(prost_types::value::Kind::NumberValue(2.0)),
            },
        );

        let jwt_payload = prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: jwt_fields,
            })),
        };

        let mut jwt_authn_fields = BTreeMap::new();
        jwt_authn_fields.insert("jwt_payload".to_string(), jwt_payload);

        let mut filter_metadata = HashMap::new();
        filter_metadata.insert(
            "envoy.filters.http.jwt_authn".to_string(),
            prost_types::Struct {
                fields: jwt_authn_fields,
            },
        );

        let req = proto::CheckRequest {
            attributes: Some(proto::AttributeContext {
                source: None,
                destination: None,
                request: Some(proto::attribute_context::Request {
                    time: None,
                    http: Some(proto::attribute_context::HttpRequest {
                        id: String::new(),
                        method: "POST".to_string(),
                        headers: Default::default(),
                        path: "/api/v1/agents".to_string(),
                        host: String::new(),
                        scheme: String::new(),
                        query: String::new(),
                        fragment: String::new(),
                        size: 0,
                        protocol: String::new(),
                        body: String::new(),
                        raw_body: vec![],
                    }),
                }),
                context_extensions: Default::default(),
                metadata_context: Some(proto::Metadata { filter_metadata }),
                tls_session: None,
            }),
        };

        let ctx = parse_check_request(&req).unwrap();

        assert_eq!(ctx.subject_id, subject_id);
        assert!(ctx.from_metadata_context);
        assert!(ctx.act.is_some());
        let act = ctx.act.unwrap();
        assert_eq!(act.sub, actor_id.to_string());
        assert_eq!(act.nhi_type, Some("agent".to_string()));
        assert_eq!(ctx.delegation_id, Some(delegation_uuid));
        assert_eq!(ctx.delegation_depth, Some(2));
    }

    #[test]
    fn test_parse_act_claim_with_nested_chain() {
        let subject_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let agent_b = Uuid::new_v4();
        let agent_a = Uuid::new_v4();

        let payload = serde_json::json!({
            "sub": subject_id.to_string(),
            "tid": tenant_id.to_string(),
            "roles": ["agent"],
            "act": {
                "sub": agent_b.to_string(),
                "nhi_type": "agent",
                "act": {
                    "sub": agent_a.to_string()
                }
            }
        });

        let req = check_request_with_bearer(&payload);
        let ctx = parse_check_request(&req).unwrap();

        assert!(ctx.act.is_some());
        let outer = ctx.act.as_ref().unwrap();
        assert_eq!(outer.sub, agent_b.to_string());
        assert_eq!(outer.nhi_type, Some("agent".to_string()));

        // Verify nested act
        assert!(outer.act.is_some());
        let inner = outer.act.as_ref().unwrap();
        assert_eq!(inner.sub, agent_a.to_string());
        assert!(inner.act.is_none());

        // Chain depth should be 2
        assert_eq!(outer.chain_depth(), 2);
    }

    #[test]
    fn test_parse_act_claim_exceeds_depth() {
        let subject_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        // Build a chain of depth 12 (> MAX_ACTOR_CHAIN_DEPTH which is 10)
        let mut act = serde_json::json!({"sub": "leaf"});
        for i in 0..11 {
            act = serde_json::json!({"sub": format!("actor-{i}"), "act": act});
        }

        let payload = serde_json::json!({
            "sub": subject_id.to_string(),
            "tid": tenant_id.to_string(),
            "roles": [],
            "act": act
        });

        let req = check_request_with_bearer(&payload);
        let ctx = parse_check_request(&req).unwrap();

        // The parse succeeds but act is None because validate_depth() rejects it
        assert!(ctx.act.is_none());
    }

    #[test]
    fn test_parse_missing_delegation_id_with_act() {
        let subject_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();

        let payload = serde_json::json!({
            "sub": subject_id.to_string(),
            "tid": tenant_id.to_string(),
            "roles": [],
            "act": {"sub": actor_id.to_string()}
        });

        let req = check_request_with_bearer(&payload);
        let ctx = parse_check_request(&req).unwrap();

        assert!(ctx.act.is_some());
        assert_eq!(ctx.act.unwrap().sub, actor_id.to_string());
        assert!(ctx.delegation_id.is_none());
        assert!(ctx.delegation_depth.is_none());
    }
}
