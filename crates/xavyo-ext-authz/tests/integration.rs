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
