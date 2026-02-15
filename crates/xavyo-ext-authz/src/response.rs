use std::collections::BTreeMap;

use uuid::Uuid;
use xavyo_core::TenantId;

use crate::error::ExtAuthzError;
use crate::proto;
use crate::request::AuthzContext;

/// Data to include in the ALLOW response's dynamic_metadata.
#[derive(Debug)]
pub struct AllowMetadata {
    pub nhi_id: Uuid,
    pub nhi_type: String,
    pub nhi_name: String,
    pub lifecycle_state: String,
    pub tenant_id: TenantId,
    pub risk_score: i32,
    pub risk_level: String,
    pub allowed_tools: Vec<String>,
    pub agent_type: Option<String>,
    pub model_provider: Option<String>,
    pub requires_human_approval: Option<bool>,
    pub decision_id: Uuid,
    /// Whether this is a delegated request (RFC 8693).
    pub is_delegated: bool,
    /// The actual actor NHI ID (if delegated).
    pub actor_nhi_id: Option<Uuid>,
    /// The delegation grant ID (if delegated).
    pub delegation_id: Option<Uuid>,
    /// The delegation depth (if delegated).
    pub delegation_depth: Option<i32>,
    /// The principal type ("user" or "nhi", if delegated).
    pub principal_type: Option<String>,
}

/// Build an ALLOW CheckResponse with dynamic_metadata.
pub fn build_allow_response(metadata: &AllowMetadata) -> proto::CheckResponse {
    let mut fields = BTreeMap::new();

    insert_string(&mut fields, "nhi_id", &metadata.nhi_id.to_string());
    insert_string(&mut fields, "nhi_type", &metadata.nhi_type);
    insert_string(&mut fields, "nhi_name", &metadata.nhi_name);
    insert_string(&mut fields, "lifecycle_state", &metadata.lifecycle_state);
    insert_string(&mut fields, "tenant_id", &metadata.tenant_id.to_string());
    insert_number(&mut fields, "risk_score", metadata.risk_score as f64);
    insert_string(&mut fields, "risk_level", &metadata.risk_level);
    insert_string_list(&mut fields, "allowed_tools", &metadata.allowed_tools);
    insert_string(
        &mut fields,
        "decision_id",
        &metadata.decision_id.to_string(),
    );

    if let Some(ref agent_type) = metadata.agent_type {
        insert_string(&mut fields, "agent_type", agent_type);
    }
    if let Some(ref model_provider) = metadata.model_provider {
        insert_string(&mut fields, "model_provider", model_provider);
    }
    if let Some(requires_approval) = metadata.requires_human_approval {
        insert_bool(&mut fields, "requires_human_approval", requires_approval);
    }

    // Delegation metadata (RFC 8693)
    insert_bool(&mut fields, "is_delegated", metadata.is_delegated);
    if let Some(ref actor_id) = metadata.actor_nhi_id {
        insert_string(&mut fields, "actor_nhi_id", &actor_id.to_string());
    }
    if let Some(ref del_id) = metadata.delegation_id {
        insert_string(&mut fields, "delegation_id", &del_id.to_string());
    }
    if let Some(depth) = metadata.delegation_depth {
        insert_number(&mut fields, "delegation_depth", depth as f64);
    }
    if let Some(ref pt) = metadata.principal_type {
        insert_string(&mut fields, "principal_type", pt);
    }

    proto::CheckResponse {
        status: Some(proto::Status {
            code: 0, // OK
            message: String::new(),
            details: vec![],
        }),
        http_response: Some(proto::check_response::HttpResponse::OkResponse(
            #[allow(deprecated)]
            proto::OkHttpResponse {
                headers: vec![],
                headers_to_remove: vec![],
                dynamic_metadata: None, // deprecated field, use top-level dynamic_metadata
                response_headers_to_add: vec![],
                query_parameters_to_set: vec![],
                query_parameters_to_remove: vec![],
            },
        )),
        dynamic_metadata: Some(prost_types::Struct { fields }),
    }
}

/// Build a DENY CheckResponse with sanitized error details.
///
/// Uses `client_message()` instead of `Display` to avoid leaking
/// operational details (UUIDs, risk scores, lifecycle states) to clients.
pub fn build_deny_response(err: &ExtAuthzError) -> proto::CheckResponse {
    let status_code = err.status_code();
    let body = serde_json::json!({
        "error": err.error_code(),
        "message": err.client_message(),
    })
    .to_string();

    let http_status = match status_code {
        400 => proto::StatusCode::BadRequest,
        401 => proto::StatusCode::Unauthorized,
        403 => proto::StatusCode::Forbidden,
        _ => proto::StatusCode::InternalServerError,
    };

    proto::CheckResponse {
        status: Some(proto::Status {
            code: 7, // PERMISSION_DENIED
            message: err.client_message().to_string(),
            details: vec![],
        }),
        http_response: Some(proto::check_response::HttpResponse::DeniedResponse(
            proto::DeniedHttpResponse {
                status: Some(proto::HttpStatus {
                    code: http_status.into(),
                }),
                headers: vec![proto::HeaderValueOption {
                    header: Some(proto::HeaderValue {
                        key: "content-type".to_string(),
                        value: String::new(),
                        raw_value: b"application/json".to_vec(),
                    }),
                    append: None,
                    append_action: 0,
                }],
                body,
            },
        )),
        dynamic_metadata: None,
    }
}

/// Build a fail-open ALLOW response with minimal tenant context.
///
/// Includes only `tenant_id`, `nhi_id` (from the parsed JWT — no DB needed),
/// an empty `allowed_tools` list (fail-safe for permissions), and a
/// `fail_open: true` flag so downstream CEL policies can detect this case.
pub fn build_fail_open_response(ctx: &AuthzContext) -> proto::CheckResponse {
    let mut fields = BTreeMap::new();

    insert_string(&mut fields, "tenant_id", &ctx.tenant_id.to_string());
    insert_string(&mut fields, "nhi_id", &ctx.subject_id.to_string());
    insert_string_list(&mut fields, "allowed_tools", &[]);
    insert_bool(&mut fields, "fail_open", true);

    proto::CheckResponse {
        status: Some(proto::Status {
            code: 0, // OK
            message: String::new(),
            details: vec![],
        }),
        http_response: None,
        dynamic_metadata: Some(prost_types::Struct { fields }),
    }
}

// --- Protobuf value helpers ---

fn insert_string(fields: &mut BTreeMap<String, prost_types::Value>, key: &str, value: &str) {
    fields.insert(
        key.to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(value.to_string())),
        },
    );
}

fn insert_number(fields: &mut BTreeMap<String, prost_types::Value>, key: &str, value: f64) {
    fields.insert(
        key.to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(value)),
        },
    );
}

fn insert_bool(fields: &mut BTreeMap<String, prost_types::Value>, key: &str, value: bool) {
    fields.insert(
        key.to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(value)),
        },
    );
}

fn insert_string_list(
    fields: &mut BTreeMap<String, prost_types::Value>,
    key: &str,
    values: &[String],
) {
    let list_values: Vec<prost_types::Value> = values
        .iter()
        .map(|v| prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(v.clone())),
        })
        .collect();

    fields.insert(
        key.to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue {
                    values: list_values,
                },
            )),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_core::TenantId;

    #[test]
    fn test_build_fail_open_response() {
        let ctx = AuthzContext {
            subject_id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            roles: vec!["agent".to_string()],
            method: "GET".to_string(),
            path: "/api/v1/tools".to_string(),
            action: "read".to_string(),
            resource_type: "tools".to_string(),
            from_metadata_context: true,
            act: None,
            delegation_id: None,
            delegation_depth: None,
        };

        let response = build_fail_open_response(&ctx);

        // Status should be OK
        assert_eq!(response.status.as_ref().unwrap().code, 0);

        // Must have dynamic_metadata with tenant context
        let dm = response.dynamic_metadata.as_ref().unwrap();
        assert!(dm.fields.contains_key("tenant_id"));
        assert!(dm.fields.contains_key("nhi_id"));

        // allowed_tools must be empty (fail-safe for permissions)
        if let Some(prost_types::value::Kind::ListValue(list)) =
            &dm.fields.get("allowed_tools").unwrap().kind
        {
            assert!(list.values.is_empty());
        } else {
            panic!("allowed_tools should be an empty list");
        }

        // fail_open flag must be true (so downstream CEL can detect)
        if let Some(prost_types::value::Kind::BoolValue(val)) =
            &dm.fields.get("fail_open").unwrap().kind
        {
            assert!(val);
        } else {
            panic!("fail_open should be a bool");
        }

        // Must NOT contain sensitive fields
        assert!(!dm.fields.contains_key("risk_score"));
        assert!(!dm.fields.contains_key("risk_level"));
        assert!(!dm.fields.contains_key("model_provider"));
        assert!(!dm.fields.contains_key("lifecycle_state"));
    }

    #[test]
    fn test_build_allow_response() {
        let metadata = AllowMetadata {
            nhi_id: Uuid::new_v4(),
            nhi_type: "agent".to_string(),
            nhi_name: "test-agent".to_string(),
            lifecycle_state: "active".to_string(),
            tenant_id: TenantId::new(),
            risk_score: 25,
            risk_level: "low".to_string(),
            allowed_tools: vec!["tool_a".to_string(), "tool_b".to_string()],
            agent_type: Some("ai_agent".to_string()),
            model_provider: Some("openai".to_string()),
            requires_human_approval: Some(false),
            decision_id: Uuid::new_v4(),
            is_delegated: false,
            actor_nhi_id: None,
            delegation_id: None,
            delegation_depth: None,
            principal_type: None,
        };

        let response = build_allow_response(&metadata);

        // Status should be OK (code 0)
        assert_eq!(response.status.as_ref().unwrap().code, 0);

        // Should have dynamic_metadata
        let dm = response.dynamic_metadata.as_ref().unwrap();
        assert!(dm.fields.contains_key("nhi_id"));
        assert!(dm.fields.contains_key("nhi_type"));
        assert!(dm.fields.contains_key("risk_score"));
        assert!(dm.fields.contains_key("allowed_tools"));
        assert!(dm.fields.contains_key("decision_id"));
        assert!(dm.fields.contains_key("agent_type"));
        assert!(dm.fields.contains_key("model_provider"));
        assert!(dm.fields.contains_key("requires_human_approval"));
        assert!(dm.fields.contains_key("tenant_id"));
        assert!(dm.fields.contains_key("lifecycle_state"));
        assert!(dm.fields.contains_key("nhi_name"));

        // Check risk_score is a number
        if let Some(prost_types::value::Kind::NumberValue(score)) =
            &dm.fields.get("risk_score").unwrap().kind
        {
            assert_eq!(*score, 25.0);
        } else {
            panic!("risk_score should be a number");
        }

        // Check allowed_tools is a list
        if let Some(prost_types::value::Kind::ListValue(list)) =
            &dm.fields.get("allowed_tools").unwrap().kind
        {
            assert_eq!(list.values.len(), 2);
        } else {
            panic!("allowed_tools should be a list");
        }

        // Check requires_human_approval is a bool
        if let Some(prost_types::value::Kind::BoolValue(val)) =
            &dm.fields.get("requires_human_approval").unwrap().kind
        {
            assert!(!val);
        } else {
            panic!("requires_human_approval should be a bool");
        }
    }

    #[test]
    fn test_build_allow_response_without_optional_fields() {
        let metadata = AllowMetadata {
            nhi_id: Uuid::new_v4(),
            nhi_type: "service_account".to_string(),
            nhi_name: "svc-test".to_string(),
            lifecycle_state: "active".to_string(),
            tenant_id: TenantId::new(),
            risk_score: 0,
            risk_level: "low".to_string(),
            allowed_tools: vec![],
            agent_type: None,
            model_provider: None,
            requires_human_approval: None,
            decision_id: Uuid::new_v4(),
            is_delegated: false,
            actor_nhi_id: None,
            delegation_id: None,
            delegation_depth: None,
            principal_type: None,
        };

        let response = build_allow_response(&metadata);
        let dm = response.dynamic_metadata.as_ref().unwrap();

        // Optional fields should be absent
        assert!(!dm.fields.contains_key("agent_type"));
        assert!(!dm.fields.contains_key("model_provider"));
        assert!(!dm.fields.contains_key("requires_human_approval"));

        // Required fields should still be present
        assert!(dm.fields.contains_key("nhi_id"));
        assert!(dm.fields.contains_key("tenant_id"));

        // Allowed tools should be an empty list
        if let Some(prost_types::value::Kind::ListValue(list)) =
            &dm.fields.get("allowed_tools").unwrap().kind
        {
            assert!(list.values.is_empty());
        } else {
            panic!("allowed_tools should be a list");
        }
    }

    #[test]
    fn test_build_deny_response() {
        let err = ExtAuthzError::NhiNotUsable("suspended".to_string());
        let response = build_deny_response(&err);

        // Status code should be non-zero (PERMISSION_DENIED)
        assert_eq!(response.status.as_ref().unwrap().code, 7);

        // Should have denied_response
        if let Some(proto::check_response::HttpResponse::DeniedResponse(denied)) =
            &response.http_response
        {
            assert!(!denied.body.is_empty());
            let body: serde_json::Value = serde_json::from_str(&denied.body).unwrap();
            assert_eq!(body["error"], "nhi_not_usable");
            // Client message is sanitized — no operational details
            assert_eq!(body["message"], "access denied");
        } else {
            panic!("expected denied_response");
        }

        // No dynamic_metadata for deny responses
        assert!(response.dynamic_metadata.is_none());
    }

    #[test]
    fn test_build_deny_response_status_codes() {
        // 400 Bad Request
        let err = ExtAuthzError::MissingAttributes;
        let response = build_deny_response(&err);
        if let Some(proto::check_response::HttpResponse::DeniedResponse(denied)) =
            &response.http_response
        {
            let expected: i32 = proto::StatusCode::BadRequest.into();
            assert_eq!(denied.status.as_ref().unwrap().code, expected);
        }

        // 401 Unauthorized
        let err = ExtAuthzError::NhiNotFound(Uuid::new_v4());
        let response = build_deny_response(&err);
        if let Some(proto::check_response::HttpResponse::DeniedResponse(denied)) =
            &response.http_response
        {
            let expected: i32 = proto::StatusCode::Unauthorized.into();
            assert_eq!(denied.status.as_ref().unwrap().code, expected);
        }

        // 403 Forbidden
        let err = ExtAuthzError::AuthorizationDenied("denied".into());
        let response = build_deny_response(&err);
        if let Some(proto::check_response::HttpResponse::DeniedResponse(denied)) =
            &response.http_response
        {
            let expected: i32 = proto::StatusCode::Forbidden.into();
            assert_eq!(denied.status.as_ref().unwrap().code, expected);
        }

        // 500 Internal Server Error
        let err = ExtAuthzError::Internal("oops".into());
        let response = build_deny_response(&err);
        if let Some(proto::check_response::HttpResponse::DeniedResponse(denied)) =
            &response.http_response
        {
            let expected: i32 = proto::StatusCode::InternalServerError.into();
            assert_eq!(denied.status.as_ref().unwrap().code, expected);
        }
    }

    #[test]
    fn test_build_deny_response_json_body() {
        let err = ExtAuthzError::RiskScoreExceeded {
            score: 80,
            threshold: 75,
        };
        let response = build_deny_response(&err);

        if let Some(proto::check_response::HttpResponse::DeniedResponse(denied)) =
            &response.http_response
        {
            let body: serde_json::Value = serde_json::from_str(&denied.body).unwrap();
            assert_eq!(body["error"], "risk_score_exceeded");
            // Client message is sanitized — no risk score details
            assert_eq!(body["message"], "access denied");

            // Check content-type header
            assert!(!denied.headers.is_empty());
            let ct = &denied.headers[0];
            assert_eq!(ct.header.as_ref().unwrap().key, "content-type");
            assert_eq!(ct.header.as_ref().unwrap().raw_value, b"application/json");
        } else {
            panic!("expected denied_response");
        }
    }
}
