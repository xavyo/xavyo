//! SCIM 2.0 discovery endpoints (RFC 7643 Section 4).
//!
//! These endpoints do NOT require authentication per the SCIM spec.

use axum::{http::StatusCode, response::Response};

use crate::handlers::common::scim_response;

/// SCIM ServiceProviderConfig (RFC 7643 Section 5).
///
/// GET /scim/v2/ServiceProviderConfig
#[utoipa::path(
    get,
    path = "/scim/v2/ServiceProviderConfig",
    responses(
        (status = 200, description = "Service provider configuration"),
    ),
    tag = "SCIM Discovery"
)]
pub async fn service_provider_config() -> Response {
    let config = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://docs.xavyo.io/scim",
        "patch": { "supported": true },
        "bulk": {
            "supported": false,
            "maxOperations": 0,
            "maxPayloadSize": 0
        },
        "filter": {
            "supported": true,
            "maxResults": 200
        },
        "changePassword": { "supported": false },
        "sort": { "supported": true },
        "etag": { "supported": false },
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token Standard (RFC 6750)",
                "specUri": "https://www.rfc-editor.org/info/rfc6750",
                "primary": true
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": "/scim/v2/ServiceProviderConfig"
        }
    });

    scim_response(StatusCode::OK, config)
}

/// SCIM ResourceTypes (RFC 7643 Section 6).
///
/// GET /scim/v2/ResourceTypes
#[utoipa::path(
    get,
    path = "/scim/v2/ResourceTypes",
    responses(
        (status = 200, description = "Supported resource types"),
    ),
    tag = "SCIM Discovery"
)]
pub async fn resource_types() -> Response {
    let resources = vec![
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            "schemaExtensions": [
                {
                    "schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
                    "required": false
                }
            ],
            "meta": {
                "resourceType": "ResourceType",
                "location": "/scim/v2/ResourceTypes/User"
            }
        }),
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Group",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "meta": {
                "resourceType": "ResourceType",
                "location": "/scim/v2/ResourceTypes/Group"
            }
        }),
    ];

    let response = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "Resources": resources
    });

    scim_response(StatusCode::OK, response)
}

/// SCIM Schemas (RFC 7643 Section 7).
///
/// GET /scim/v2/Schemas
#[utoipa::path(
    get,
    path = "/scim/v2/Schemas",
    responses(
        (status = 200, description = "Supported schemas"),
    ),
    tag = "SCIM Discovery"
)]
pub async fn schemas() -> Response {
    let resources = vec![
        serde_json::json!({
            "id": "urn:ietf:params:scim:schemas:core:2.0:User",
            "name": "User",
            "description": "User Account",
            "attributes": [
                { "name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server" },
                { "name": "displayName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none" },
                { "name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default" },
                { "name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none" },
                { "name": "name", "type": "complex", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default",
                  "subAttributes": [
                      { "name": "givenName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default" },
                      { "name": "familyName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default" }
                  ]
                },
                { "name": "groups", "type": "complex", "multiValued": true, "required": false, "mutability": "readOnly", "returned": "default" }
            ],
            "meta": {
                "resourceType": "Schema",
                "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
            }
        }),
        serde_json::json!({
            "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "name": "Group",
            "description": "Group",
            "attributes": [
                { "name": "displayName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server" },
                { "name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default" },
                { "name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default" }
            ],
            "meta": {
                "resourceType": "Schema",
                "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"
            }
        }),
        serde_json::json!({
            "id": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            "name": "Enterprise User",
            "description": "Enterprise User Extension",
            "attributes": [
                { "name": "department", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default" },
                { "name": "costCenter", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default" },
                { "name": "employeeNumber", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default" },
                { "name": "manager", "type": "complex", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default" }
            ],
            "meta": {
                "resourceType": "Schema",
                "location": "/scim/v2/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
            }
        }),
    ];

    let response = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "Resources": resources
    });

    scim_response(StatusCode::OK, response)
}
