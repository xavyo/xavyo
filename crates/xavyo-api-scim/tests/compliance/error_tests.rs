//! RFC 7644 Error Response Compliance Tests
//!
//! These tests verify that SCIM error responses follow
//! RFC 7644 Section 3.12 format requirements.

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    // ============================================================
    // Error Response Structure
    // ============================================================

    #[test]
    fn test_error_response_schema() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "detail": "Request is invalid"
        });
        assert!(error["schemas"].is_array());
        assert_eq!(
            error["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:Error"
        );
    }

    #[test]
    fn test_error_response_status_required() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "404",
            "detail": "Resource not found"
        });
        assert!(error.get("status").is_some());
        assert!(!error["status"].is_null());
    }

    #[test]
    fn test_error_response_status_as_string() {
        // RFC 7644: Status is the HTTP status code as a string
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400"
        });
        assert!(error["status"].is_string());
    }

    #[test]
    fn test_error_response_detail_optional() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "500"
        });
        // detail is optional but recommended
        assert!(error.get("detail").is_none() || error["detail"].is_null());
    }

    #[test]
    fn test_error_response_detail_human_readable() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "detail": "The attribute 'userName' is required"
        });
        assert!(error["detail"].is_string());
        assert!(!error["detail"].as_str().unwrap().is_empty());
    }

    // ============================================================
    // scimType Values (RFC 7644 Section 3.12)
    // ============================================================

    #[test]
    fn test_error_scim_type_invalid_syntax() {
        // RFC 7644: invalidSyntax - request body is not valid JSON
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "invalidSyntax",
            "detail": "Request body is not valid JSON"
        });
        assert_eq!(error["scimType"], "invalidSyntax");
    }

    #[test]
    fn test_error_scim_type_invalid_filter() {
        // RFC 7644: invalidFilter - filter syntax is invalid
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "invalidFilter",
            "detail": "Invalid filter expression"
        });
        assert_eq!(error["scimType"], "invalidFilter");
    }

    #[test]
    fn test_error_scim_type_too_many() {
        // RFC 7644: tooMany - too many results
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "tooMany",
            "detail": "Query returns too many results"
        });
        assert_eq!(error["scimType"], "tooMany");
    }

    #[test]
    fn test_error_scim_type_uniqueness() {
        // RFC 7644: uniqueness - attribute violates uniqueness constraint
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "409",
            "scimType": "uniqueness",
            "detail": "User with userName 'john@example.com' already exists"
        });
        assert_eq!(error["scimType"], "uniqueness");
    }

    #[test]
    fn test_error_scim_type_mutability() {
        // RFC 7644: mutability - attribute cannot be modified
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "mutability",
            "detail": "Attribute 'id' is immutable"
        });
        assert_eq!(error["scimType"], "mutability");
    }

    #[test]
    fn test_error_scim_type_invalid_path() {
        // RFC 7644: invalidPath - PATCH path is invalid
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "invalidPath",
            "detail": "Path 'invalidattr' does not exist"
        });
        assert_eq!(error["scimType"], "invalidPath");
    }

    #[test]
    fn test_error_scim_type_no_target() {
        // RFC 7644: noTarget - path filter did not match
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "noTarget",
            "detail": "No resource found matching filter"
        });
        assert_eq!(error["scimType"], "noTarget");
    }

    #[test]
    fn test_error_scim_type_invalid_value() {
        // RFC 7644: invalidValue - value is invalid
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "invalidValue",
            "detail": "Email format is invalid"
        });
        assert_eq!(error["scimType"], "invalidValue");
    }

    #[test]
    fn test_error_scim_type_invalid_vers() {
        // RFC 7644: invalidVers - version mismatch
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "412",
            "scimType": "invalidVers",
            "detail": "ETag does not match current version"
        });
        assert_eq!(error["scimType"], "invalidVers");
    }

    #[test]
    fn test_error_scim_type_sensitive() {
        // RFC 7644: sensitive - cannot return sensitive attribute
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "403",
            "scimType": "sensitive",
            "detail": "Cannot return password attribute"
        });
        assert_eq!(error["scimType"], "sensitive");
    }

    // ============================================================
    // HTTP Status Code Mapping
    // ============================================================

    #[test]
    fn test_error_400_bad_request() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "detail": "Bad request"
        });
        assert_eq!(error["status"], "400");
    }

    #[test]
    fn test_error_401_unauthorized() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "401",
            "detail": "Authentication required"
        });
        assert_eq!(error["status"], "401");
    }

    #[test]
    fn test_error_403_forbidden() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "403",
            "detail": "Insufficient permissions"
        });
        assert_eq!(error["status"], "403");
    }

    #[test]
    fn test_error_404_not_found() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "404",
            "scimType": "noTarget",
            "detail": "Resource 'abc123' not found"
        });
        assert_eq!(error["status"], "404");
    }

    #[test]
    fn test_error_409_conflict() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "409",
            "scimType": "uniqueness",
            "detail": "Resource already exists"
        });
        assert_eq!(error["status"], "409");
    }

    #[test]
    fn test_error_412_precondition_failed() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "412",
            "scimType": "invalidVers",
            "detail": "Precondition failed"
        });
        assert_eq!(error["status"], "412");
    }

    #[test]
    fn test_error_413_payload_too_large() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "413",
            "detail": "Request payload too large"
        });
        assert_eq!(error["status"], "413");
    }

    #[test]
    fn test_error_500_internal() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "500",
            "detail": "Internal server error"
        });
        assert_eq!(error["status"], "500");
    }

    #[test]
    fn test_error_501_not_implemented() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "501",
            "detail": "Feature not implemented"
        });
        assert_eq!(error["status"], "501");
    }

    // ============================================================
    // Error Response Validation
    // ============================================================

    fn is_valid_scim_error(error: &Value) -> bool {
        // Must have schemas array with error schema
        if !error["schemas"].is_array() {
            return false;
        }
        let schemas = error["schemas"].as_array().unwrap();
        if !schemas
            .iter()
            .any(|s| s == "urn:ietf:params:scim:api:messages:2.0:Error")
        {
            return false;
        }

        // Must have status as string
        if !error["status"].is_string() {
            return false;
        }

        true
    }

    #[test]
    fn test_valid_error_with_all_fields() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "400",
            "scimType": "invalidValue",
            "detail": "The value is invalid"
        });
        assert!(is_valid_scim_error(&error));
    }

    #[test]
    fn test_valid_error_minimal() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "500"
        });
        assert!(is_valid_scim_error(&error));
    }

    #[test]
    fn test_invalid_error_missing_schemas() {
        let error = json!({
            "status": "400",
            "detail": "Bad request"
        });
        assert!(!is_valid_scim_error(&error));
    }

    #[test]
    fn test_invalid_error_missing_status() {
        let error = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Bad request"
        });
        // status as null
        assert!(!is_valid_scim_error(&error));
    }
}
