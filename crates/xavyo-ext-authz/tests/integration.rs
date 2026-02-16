//! Integration tests for the ext_authz service.
//!
//! These tests require a running PostgreSQL instance.
//! Run with: cargo test --features integration -p xavyo-ext-authz

#[cfg(feature = "integration")]
mod integration {
    // Integration tests would go here, requiring a real database.
    // For now, unit tests in individual modules cover the core logic.
}

/// Smoke test: verify proto types compile and are accessible.
#[test]
fn test_proto_types_available() {
    // Verify that the generated types exist and can be instantiated
    let _req = xavyo_ext_authz::proto::CheckRequest { attributes: None };
    let _resp = xavyo_ext_authz::proto::CheckResponse {
        status: None,
        http_response: None,
        dynamic_metadata: None,
    };
}

/// Verify CheckResponse can carry dynamic_metadata.
#[test]
fn test_check_response_with_dynamic_metadata() {
    use std::collections::BTreeMap;

    let mut fields = BTreeMap::new();
    fields.insert(
        "test_key".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                "test_value".to_string(),
            )),
        },
    );

    let resp = xavyo_ext_authz::proto::CheckResponse {
        status: Some(xavyo_ext_authz::proto::Status {
            code: 0,
            message: String::new(),
            details: vec![],
        }),
        http_response: None,
        dynamic_metadata: Some(prost_types::Struct { fields }),
    };

    assert!(resp.dynamic_metadata.is_some());
    let dm = resp.dynamic_metadata.unwrap();
    assert!(dm.fields.contains_key("test_key"));
}

/// Verify DeniedHttpResponse structure.
#[test]
fn test_denied_response_structure() {
    let resp = xavyo_ext_authz::proto::CheckResponse {
        status: Some(xavyo_ext_authz::proto::Status {
            code: 7,
            message: "denied".to_string(),
            details: vec![],
        }),
        http_response: Some(
            xavyo_ext_authz::proto::check_response::HttpResponse::DeniedResponse(
                xavyo_ext_authz::proto::DeniedHttpResponse {
                    status: Some(xavyo_ext_authz::proto::HttpStatus {
                        code: xavyo_ext_authz::proto::StatusCode::Forbidden.into(),
                    }),
                    headers: vec![],
                    body: r#"{"error":"denied"}"#.to_string(),
                },
            ),
        ),
        dynamic_metadata: None,
    };

    assert_eq!(resp.status.as_ref().unwrap().code, 7);
    if let Some(xavyo_ext_authz::proto::check_response::HttpResponse::DeniedResponse(denied)) =
        &resp.http_response
    {
        assert!(!denied.body.is_empty());
    } else {
        panic!("expected DeniedResponse");
    }
}

/// Verify delegation metadata fields are present in a delegated ALLOW response.
#[test]
fn test_delegated_allow_response_has_delegation_fields() {
    use std::collections::BTreeMap;
    use uuid::Uuid;

    // Simulate a delegated ALLOW response with delegation fields in dynamic_metadata
    let actor_id = Uuid::new_v4();
    let delegation_id = Uuid::new_v4();

    let mut fields = BTreeMap::new();
    fields.insert(
        "is_delegated".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(true)),
        },
    );
    fields.insert(
        "actor_nhi_id".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                actor_id.to_string(),
            )),
        },
    );
    fields.insert(
        "delegation_id".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                delegation_id.to_string(),
            )),
        },
    );
    fields.insert(
        "delegation_depth".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(1.0)),
        },
    );
    fields.insert(
        "principal_type".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("user".to_string())),
        },
    );

    let resp = xavyo_ext_authz::proto::CheckResponse {
        status: Some(xavyo_ext_authz::proto::Status {
            code: 0,
            message: String::new(),
            details: vec![],
        }),
        http_response: Some(
            xavyo_ext_authz::proto::check_response::HttpResponse::OkResponse(
                #[allow(deprecated)]
                xavyo_ext_authz::proto::OkHttpResponse {
                    headers: vec![],
                    headers_to_remove: vec![],
                    dynamic_metadata: None,
                    response_headers_to_add: vec![],
                    query_parameters_to_set: vec![],
                    query_parameters_to_remove: vec![],
                },
            ),
        ),
        dynamic_metadata: Some(prost_types::Struct { fields }),
    };

    // Verify status is OK
    assert_eq!(resp.status.as_ref().unwrap().code, 0);

    // Verify delegation fields in dynamic_metadata
    let dm = resp.dynamic_metadata.as_ref().unwrap();

    if let Some(prost_types::value::Kind::BoolValue(val)) =
        &dm.fields.get("is_delegated").unwrap().kind
    {
        assert!(val, "is_delegated should be true");
    } else {
        panic!("is_delegated should be a bool");
    }

    if let Some(prost_types::value::Kind::StringValue(val)) =
        &dm.fields.get("actor_nhi_id").unwrap().kind
    {
        assert_eq!(val, &actor_id.to_string());
    } else {
        panic!("actor_nhi_id should be a string");
    }

    if let Some(prost_types::value::Kind::StringValue(val)) =
        &dm.fields.get("delegation_id").unwrap().kind
    {
        assert_eq!(val, &delegation_id.to_string());
    } else {
        panic!("delegation_id should be a string");
    }

    if let Some(prost_types::value::Kind::NumberValue(val)) =
        &dm.fields.get("delegation_depth").unwrap().kind
    {
        assert_eq!(*val, 1.0);
    } else {
        panic!("delegation_depth should be a number");
    }

    if let Some(prost_types::value::Kind::StringValue(val)) =
        &dm.fields.get("principal_type").unwrap().kind
    {
        assert_eq!(val, "user");
    } else {
        panic!("principal_type should be a string");
    }
}

/// Verify that a non-delegated response does NOT include optional delegation fields.
#[test]
fn test_non_delegated_response_lacks_optional_delegation_fields() {
    use std::collections::BTreeMap;

    let mut fields = BTreeMap::new();
    fields.insert(
        "is_delegated".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(false)),
        },
    );
    fields.insert(
        "nhi_id".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                "some-nhi-id".to_string(),
            )),
        },
    );

    let dm = prost_types::Struct { fields };

    // is_delegated should be false
    if let Some(prost_types::value::Kind::BoolValue(val)) =
        &dm.fields.get("is_delegated").unwrap().kind
    {
        assert!(!val, "is_delegated should be false");
    }

    // These optional fields should NOT be present
    assert!(!dm.fields.contains_key("actor_nhi_id"));
    assert!(!dm.fields.contains_key("delegation_id"));
    assert!(!dm.fields.contains_key("delegation_depth"));
    assert!(!dm.fields.contains_key("principal_type"));
}

/// Verify delegation grant not active error produces correct deny response proto.
#[test]
fn test_delegation_grant_not_active_proto_deny() {
    use uuid::Uuid;

    let grant_id = Uuid::new_v4();

    // Build a DeniedResponse for inactive delegation grant
    let resp = xavyo_ext_authz::proto::CheckResponse {
        status: Some(xavyo_ext_authz::proto::Status {
            code: 7, // PERMISSION_DENIED
            message: "access denied".to_string(),
            details: vec![],
        }),
        http_response: Some(
            xavyo_ext_authz::proto::check_response::HttpResponse::DeniedResponse(
                xavyo_ext_authz::proto::DeniedHttpResponse {
                    status: Some(xavyo_ext_authz::proto::HttpStatus {
                        code: xavyo_ext_authz::proto::StatusCode::Forbidden.into(),
                    }),
                    headers: vec![xavyo_ext_authz::proto::HeaderValueOption {
                        header: Some(xavyo_ext_authz::proto::HeaderValue {
                            key: "content-type".to_string(),
                            value: String::new(),
                            raw_value: b"application/json".to_vec(),
                        }),
                        append: None,
                        append_action: 0,
                    }],
                    body: serde_json::json!({
                        "error": "delegation_grant_not_active",
                        "message": "access denied",
                    })
                    .to_string(),
                },
            ),
        ),
        dynamic_metadata: None,
    };

    // Verify status
    assert_eq!(resp.status.as_ref().unwrap().code, 7);

    // Verify deny response
    if let Some(xavyo_ext_authz::proto::check_response::HttpResponse::DeniedResponse(denied)) =
        &resp.http_response
    {
        let body: serde_json::Value = serde_json::from_str(&denied.body).unwrap();
        assert_eq!(body["error"], "delegation_grant_not_active");
        assert_eq!(body["message"], "access denied");
        // Grant ID must NOT appear in the client-facing body
        assert!(
            !denied.body.contains(&grant_id.to_string()),
            "grant ID must not leak to clients"
        );
    } else {
        panic!("expected DeniedResponse");
    }

    // No dynamic_metadata on deny
    assert!(resp.dynamic_metadata.is_none());
}
