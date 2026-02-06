//! Organization security policy management handlers (F-066).
//!
//! Endpoints for managing organization-level security policies with inheritance.

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Extension, Json,
};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::org_security_policy::{OrgPolicyType, PolicySource};
use xavyo_db::models::Group;

use crate::error::ApiAuthError;
use crate::models::{
    CreateOrgSecurityPolicyRequest, EffectiveOrgPolicyResponse, EffectiveUserPolicyResponse,
    IpRestrictionPolicyConfig, ListOrgPoliciesQuery, MfaPolicyConfig, OrgPolicyTypeDto,
    OrgSecurityPolicyListResponse, OrgSecurityPolicyResponse, PasswordPolicyConfig,
    PolicySourceDto, PolicySourceInfo, PolicyValidationResponse, SessionPolicyConfig,
    UpdateOrgSecurityPolicyRequest, ValidatePolicyRequest,
};
use crate::services::{OrgPolicyError, OrgPolicyService};

/// Convert OrgPolicyError to ApiAuthError.
fn to_api_error(err: OrgPolicyError) -> ApiAuthError {
    match err {
        OrgPolicyError::Database(e) => ApiAuthError::Database(e),
        OrgPolicyError::OrgNotFound(_) => ApiAuthError::OrgNotFound,
        OrgPolicyError::PolicyNotFound => ApiAuthError::OrgPolicyNotFound,
        OrgPolicyError::InvalidConfig(msg) => ApiAuthError::InvalidPolicyConfig(msg),
        OrgPolicyError::Validation(msg) => ApiAuthError::Validation(msg),
    }
}

/// Convert string to OrgPolicyTypeDto.
fn str_to_policy_type_dto(s: &str) -> Option<OrgPolicyTypeDto> {
    match s {
        "password" => Some(OrgPolicyTypeDto::Password),
        "mfa" => Some(OrgPolicyTypeDto::Mfa),
        "session" => Some(OrgPolicyTypeDto::Session),
        "ip_restriction" => Some(OrgPolicyTypeDto::IpRestriction),
        _ => None,
    }
}

/// Convert DTO to OrgPolicyType.
fn from_policy_type_dto(dto: &OrgPolicyTypeDto) -> OrgPolicyType {
    match dto {
        OrgPolicyTypeDto::Password => OrgPolicyType::Password,
        OrgPolicyTypeDto::Mfa => OrgPolicyType::Mfa,
        OrgPolicyTypeDto::Session => OrgPolicyType::Session,
        OrgPolicyTypeDto::IpRestriction => OrgPolicyType::IpRestriction,
    }
}

/// Parse policy type from string (case-insensitive).
fn parse_policy_type(s: &str) -> Result<OrgPolicyType, ApiAuthError> {
    OrgPolicyType::parse(&s.to_lowercase()).ok_or_else(|| {
        ApiAuthError::InvalidPolicyType(format!(
            "Invalid policy type: {s}. Must be one of: password, mfa, session, ip_restriction"
        ))
    })
}

/// Parse claims.sub (String) to Uuid.
fn parse_user_id(claims: &JwtClaims) -> Result<Uuid, ApiAuthError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiAuthError::Unauthorized)
}

/// Validate policy configuration based on policy type.
fn validate_policy_config(
    policy_type: &OrgPolicyType,
    config: &serde_json::Value,
) -> Result<(), ApiAuthError> {
    match policy_type {
        OrgPolicyType::Password => {
            let cfg: PasswordPolicyConfig =
                serde_json::from_value(config.clone()).map_err(|e| {
                    ApiAuthError::InvalidPolicyConfig(format!(
                        "Invalid password policy config: {e}"
                    ))
                })?;
            cfg.validate()
                .map_err(|errs| ApiAuthError::InvalidPolicyConfig(errs.join("; ")))?;
        }
        OrgPolicyType::Mfa => {
            let cfg: MfaPolicyConfig = serde_json::from_value(config.clone()).map_err(|e| {
                ApiAuthError::InvalidPolicyConfig(format!("Invalid MFA policy config: {e}"))
            })?;
            cfg.validate()
                .map_err(|errs| ApiAuthError::InvalidPolicyConfig(errs.join("; ")))?;
        }
        OrgPolicyType::Session => {
            let cfg: SessionPolicyConfig = serde_json::from_value(config.clone()).map_err(|e| {
                ApiAuthError::InvalidPolicyConfig(format!("Invalid session policy config: {e}"))
            })?;
            cfg.validate()
                .map_err(|errs| ApiAuthError::InvalidPolicyConfig(errs.join("; ")))?;
        }
        OrgPolicyType::IpRestriction => {
            let cfg: IpRestrictionPolicyConfig =
                serde_json::from_value(config.clone()).map_err(|e| {
                    ApiAuthError::InvalidPolicyConfig(format!("Invalid IP restriction config: {e}"))
                })?;
            cfg.validate()
                .map_err(|errs| ApiAuthError::InvalidPolicyConfig(errs.join("; ")))?;
        }
    }
    Ok(())
}

/// Convert a PolicySource to PolicySourceInfo DTO.
fn policy_source_to_dto(source: &PolicySource) -> PolicySourceInfo {
    match source {
        PolicySource::Local {
            group_id,
            group_name,
        } => PolicySourceInfo {
            source_type: PolicySourceDto::Local,
            group_id: Some(*group_id),
            group_name: Some(group_name.clone()),
        },
        PolicySource::Inherited {
            group_id,
            group_name,
        } => PolicySourceInfo {
            source_type: PolicySourceDto::Inherited,
            group_id: Some(*group_id),
            group_name: Some(group_name.clone()),
        },
        PolicySource::TenantDefault => PolicySourceInfo {
            source_type: PolicySourceDto::TenantDefault,
            group_id: None,
            group_name: None,
        },
    }
}

/// GET /admin/organizations/:org_id/security-policies
///
/// List all security policies for an organization.
pub async fn list_org_policies(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path(org_id): Path<Uuid>,
    Query(query): Query<ListOrgPoliciesQuery>,
) -> Result<(StatusCode, Json<OrgSecurityPolicyListResponse>), ApiAuthError> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;

    // Verify org belongs to tenant
    let group = Group::find_by_id(&pool, tenant_id, org_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::OrgNotFound)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    let policies = service
        .list_policies_for_org(tenant_id, org_id)
        .await
        .map_err(to_api_error)?;

    // Filter by policy type if specified
    let mut filtered: Vec<_> = policies
        .into_iter()
        .filter(|p| {
            if let Some(ref pt) = query.policy_type {
                p.policy_type == from_policy_type_dto(pt).as_str()
            } else {
                true
            }
        })
        .filter(|p| {
            if let Some(active) = query.is_active {
                p.is_active == active
            } else {
                true
            }
        })
        .collect();

    let total = filtered.len();

    let items: Vec<OrgSecurityPolicyResponse> = filtered
        .drain(..)
        .map(|p| OrgSecurityPolicyResponse {
            id: p.id,
            tenant_id: p.tenant_id,
            group_id: p.group_id,
            group_name: Some(group.display_name.clone()),
            policy_type: str_to_policy_type_dto(&p.policy_type)
                .unwrap_or(OrgPolicyTypeDto::Password),
            config: p.config,
            is_active: p.is_active,
            created_at: p.created_at,
            updated_at: p.updated_at,
            created_by: p.created_by,
            updated_by: p.updated_by,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(OrgSecurityPolicyListResponse { items, total }),
    ))
}

/// POST /admin/organizations/:org_id/security-policies
///
/// Create a new security policy for an organization.
pub async fn create_org_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path(org_id): Path<Uuid>,
    Json(request): Json<CreateOrgSecurityPolicyRequest>,
) -> Result<(StatusCode, Json<OrgSecurityPolicyResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;
    let user_id = parse_user_id(&claims)?;

    // Verify org belongs to tenant
    let group = Group::find_by_id(&pool, tenant_id, org_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::OrgNotFound)?;

    let policy_type = from_policy_type_dto(&request.policy_type);

    // Validate config
    validate_policy_config(&policy_type, &request.config)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    let policy = service
        .upsert_policy(
            tenant_id,
            org_id,
            policy_type,
            request.config.clone(),
            request.is_active,
            Some(user_id),
        )
        .await
        .map_err(to_api_error)?;

    info!(
        tenant_id = %tenant_id,
        org_id = %org_id,
        policy_type = %policy_type,
        created_by = %user_id,
        "Organization security policy created"
    );

    Ok((
        StatusCode::CREATED,
        Json(OrgSecurityPolicyResponse {
            id: policy.id,
            tenant_id: policy.tenant_id,
            group_id: policy.group_id,
            group_name: Some(group.display_name),
            policy_type: str_to_policy_type_dto(&policy.policy_type)
                .unwrap_or(OrgPolicyTypeDto::Password),
            config: policy.config,
            is_active: policy.is_active,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
            created_by: policy.created_by,
            updated_by: policy.updated_by,
        }),
    ))
}

/// GET /admin/organizations/:org_id/security-policies/:policy_type
///
/// Get a specific policy for an organization.
pub async fn get_org_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path((org_id, policy_type_str)): Path<(Uuid, String)>,
) -> Result<(StatusCode, Json<OrgSecurityPolicyResponse>), ApiAuthError> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;

    // Verify org belongs to tenant
    let group = Group::find_by_id(&pool, tenant_id, org_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::OrgNotFound)?;

    let policy_type = parse_policy_type(&policy_type_str)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    let policy = service
        .get_policy(tenant_id, org_id, policy_type)
        .await
        .map_err(to_api_error)?
        .ok_or(ApiAuthError::OrgPolicyNotFound)?;

    Ok((
        StatusCode::OK,
        Json(OrgSecurityPolicyResponse {
            id: policy.id,
            tenant_id: policy.tenant_id,
            group_id: policy.group_id,
            group_name: Some(group.display_name),
            policy_type: str_to_policy_type_dto(&policy.policy_type)
                .unwrap_or(OrgPolicyTypeDto::Password),
            config: policy.config,
            is_active: policy.is_active,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
            created_by: policy.created_by,
            updated_by: policy.updated_by,
        }),
    ))
}

/// PUT /admin/organizations/:org_id/security-policies/:policy_type
///
/// Create or update a policy for an organization.
pub async fn upsert_org_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path((org_id, policy_type_str)): Path<(Uuid, String)>,
    Json(request): Json<UpdateOrgSecurityPolicyRequest>,
) -> Result<(StatusCode, Json<OrgSecurityPolicyResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;
    let user_id = parse_user_id(&claims)?;

    // Verify org belongs to tenant
    let group = Group::find_by_id(&pool, tenant_id, org_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::OrgNotFound)?;

    let policy_type = parse_policy_type(&policy_type_str)?;

    // Validate config
    validate_policy_config(&policy_type, &request.config)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    // Check if policy exists to determine status code
    let existing = service
        .get_policy(tenant_id, org_id, policy_type)
        .await
        .map_err(to_api_error)?;

    let policy = service
        .upsert_policy(
            tenant_id,
            org_id,
            policy_type,
            request.config.clone(),
            request.is_active.unwrap_or(true),
            Some(user_id),
        )
        .await
        .map_err(to_api_error)?;

    let status = if existing.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    info!(
        tenant_id = %tenant_id,
        org_id = %org_id,
        policy_type = %policy_type,
        updated_by = %user_id,
        "Organization security policy upserted"
    );

    Ok((
        status,
        Json(OrgSecurityPolicyResponse {
            id: policy.id,
            tenant_id: policy.tenant_id,
            group_id: policy.group_id,
            group_name: Some(group.display_name),
            policy_type: str_to_policy_type_dto(&policy.policy_type)
                .unwrap_or(OrgPolicyTypeDto::Password),
            config: policy.config,
            is_active: policy.is_active,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
            created_by: policy.created_by,
            updated_by: policy.updated_by,
        }),
    ))
}

/// DELETE /admin/organizations/:org_id/security-policies/:policy_type
///
/// Delete a policy for an organization.
pub async fn delete_org_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path((org_id, policy_type_str)): Path<(Uuid, String)>,
) -> Result<StatusCode, ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;

    // Verify org belongs to tenant
    let _group = Group::find_by_id(&pool, tenant_id, org_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::OrgNotFound)?;

    let policy_type = parse_policy_type(&policy_type_str)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    service
        .delete_policy(tenant_id, org_id, policy_type)
        .await
        .map_err(to_api_error)?;

    info!(
        tenant_id = %tenant_id,
        org_id = %org_id,
        policy_type = %policy_type,
        deleted_by = %claims.sub,
        "Organization security policy deleted"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// GET /admin/organizations/:org_id/effective-policy/:policy_type
///
/// Get the effective (resolved) policy for an organization.
pub async fn get_effective_org_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path((org_id, policy_type_str)): Path<(Uuid, String)>,
) -> Result<(StatusCode, Json<EffectiveOrgPolicyResponse>), ApiAuthError> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;

    // Verify org belongs to tenant
    let _group = Group::find_by_id(&pool, tenant_id, org_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::OrgNotFound)?;

    let policy_type = parse_policy_type(&policy_type_str)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    let effective = service
        .get_effective_policy_for_org(tenant_id, org_id, policy_type)
        .await
        .map_err(to_api_error)?;

    let source = policy_source_to_dto(&effective.source);

    Ok((
        StatusCode::OK,
        Json(EffectiveOrgPolicyResponse {
            config: effective.config,
            source,
        }),
    ))
}

/// GET /admin/users/:user_id/effective-policy/:policy_type
///
/// Get the effective policy for a user (most restrictive across all groups).
pub async fn get_effective_user_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path((user_id, policy_type_str)): Path<(Uuid, String)>,
) -> Result<(StatusCode, Json<EffectiveUserPolicyResponse>), ApiAuthError> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;

    let policy_type = parse_policy_type(&policy_type_str)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    let (config, sources) = service
        .get_effective_policy_for_user(tenant_id, user_id, policy_type)
        .await
        .map_err(to_api_error)?;

    let source_infos: Vec<PolicySourceInfo> = sources.iter().map(policy_source_to_dto).collect();

    let resolution_method = if source_infos.len() > 1 {
        "most_restrictive".to_string()
    } else {
        "single_source".to_string()
    };

    Ok((
        StatusCode::OK,
        Json(EffectiveUserPolicyResponse {
            config,
            sources: source_infos,
            resolution_method,
        }),
    ))
}

/// POST /admin/organizations/:org_id/security-policies/validate
///
/// Validate a policy configuration for conflicts.
pub async fn validate_org_policy(
    Extension(pool): Extension<PgPool>,
    Extension(claims): Extension<JwtClaims>,
    Path(org_id): Path<Uuid>,
    Json(request): Json<ValidatePolicyRequest>,
) -> Result<(StatusCode, Json<PolicyValidationResponse>), ApiAuthError> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAuthError::Unauthorized)?;

    // Verify org belongs to tenant
    let _group = Group::find_by_id(&pool, tenant_id, org_id)
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::OrgNotFound)?;

    let policy_type = from_policy_type_dto(&request.policy_type);

    // First validate the config structure
    validate_policy_config(&policy_type, &request.config)?;

    let service = OrgPolicyService::new(Arc::new(pool.clone()));

    let result = service
        .validate_policy(tenant_id, org_id, policy_type, &request.config)
        .await
        .map_err(to_api_error)?;

    Ok((
        StatusCode::OK,
        Json(PolicyValidationResponse {
            valid: result.valid,
            warnings: result.warnings,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_policy_type() {
        assert!(parse_policy_type("password").is_ok());
        assert!(parse_policy_type("mfa").is_ok());
        assert!(parse_policy_type("session").is_ok());
        assert!(parse_policy_type("ip_restriction").is_ok());
        assert!(parse_policy_type("PASSWORD").is_ok());
        assert!(parse_policy_type("invalid").is_err());
    }

    #[test]
    fn test_validate_password_policy_config() {
        let valid = serde_json::json!({
            "min_length": 12,
            "require_uppercase": true
        });
        assert!(validate_policy_config(&OrgPolicyType::Password, &valid).is_ok());

        let invalid = serde_json::json!({
            "min_length": 5 // Too short
        });
        assert!(validate_policy_config(&OrgPolicyType::Password, &invalid).is_err());
    }

    #[test]
    fn test_validate_mfa_policy_config() {
        let valid = serde_json::json!({
            "required": true,
            "allowed_methods": ["totp", "webauthn"]
        });
        assert!(validate_policy_config(&OrgPolicyType::Mfa, &valid).is_ok());

        let invalid = serde_json::json!({
            "allowed_methods": ["invalid_method"]
        });
        assert!(validate_policy_config(&OrgPolicyType::Mfa, &invalid).is_err());
    }

    #[test]
    fn test_str_to_policy_type_dto() {
        assert_eq!(
            str_to_policy_type_dto("password"),
            Some(OrgPolicyTypeDto::Password)
        );
        assert_eq!(str_to_policy_type_dto("mfa"), Some(OrgPolicyTypeDto::Mfa));
        assert_eq!(
            str_to_policy_type_dto("session"),
            Some(OrgPolicyTypeDto::Session)
        );
        assert_eq!(
            str_to_policy_type_dto("ip_restriction"),
            Some(OrgPolicyTypeDto::IpRestriction)
        );
        assert_eq!(str_to_policy_type_dto("invalid"), None);
    }

    #[test]
    fn test_policy_source_to_dto() {
        let local = PolicySource::Local {
            group_id: Uuid::nil(),
            group_name: "Finance".to_string(),
        };
        let dto = policy_source_to_dto(&local);
        assert!(matches!(dto.source_type, PolicySourceDto::Local));
        assert_eq!(dto.group_id, Some(Uuid::nil()));
        assert_eq!(dto.group_name, Some("Finance".to_string()));

        let tenant = PolicySource::TenantDefault;
        let dto = policy_source_to_dto(&tenant);
        assert!(matches!(dto.source_type, PolicySourceDto::TenantDefault));
        assert!(dto.group_id.is_none());
    }
}
