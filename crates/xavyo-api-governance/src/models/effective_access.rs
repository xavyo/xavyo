//! Effective access request/response models for governance API.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::services::effective_access_service::{
    EffectiveAccessResult, EffectiveEntitlement, EntitlementSource,
};

/// Query parameters for effective access.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct EffectiveAccessQuery {
    /// Optional filter by application ID.
    pub application_id: Option<Uuid>,
}

/// Source of an entitlement assignment (API response format).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntitlementSourceResponse {
    /// Direct user assignment.
    Direct,
    /// Inherited from group membership.
    Group {
        /// Group ID.
        group_id: Uuid,
        /// Group name.
        group_name: String,
    },
    /// Inherited from role (legacy string-based roles).
    Role {
        /// Role name.
        role_name: String,
    },
    /// From governance role hierarchy (F088).
    GovRole {
        /// The role ID the user is assigned to.
        role_id: Uuid,
        /// The role name the user is assigned to.
        role_name: String,
        /// The source role ID that grants the entitlement (may be ancestor).
        source_role_id: Uuid,
        /// The source role name.
        source_role_name: String,
        /// Whether entitlement is inherited from an ancestor role.
        is_inherited: bool,
    },
}

impl From<EntitlementSource> for EntitlementSourceResponse {
    fn from(source: EntitlementSource) -> Self {
        match source {
            EntitlementSource::Direct => Self::Direct,
            EntitlementSource::Group {
                group_id,
                group_name,
            } => Self::Group {
                group_id,
                group_name,
            },
            EntitlementSource::Role { role_name } => Self::Role { role_name },
            EntitlementSource::GovRole {
                role_id,
                role_name,
                source_role_id,
                source_role_name,
                is_inherited,
            } => Self::GovRole {
                role_id,
                role_name,
                source_role_id,
                source_role_name,
                is_inherited,
            },
        }
    }
}

/// An effective entitlement with its sources (API response format).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveEntitlementResponse {
    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name.
    pub entitlement_name: String,

    /// Application ID.
    pub application_id: Uuid,

    /// Risk level.
    pub risk_level: String,

    /// All sources that grant this entitlement.
    pub sources: Vec<EntitlementSourceResponse>,
}

impl From<EffectiveEntitlement> for EffectiveEntitlementResponse {
    fn from(ee: EffectiveEntitlement) -> Self {
        Self {
            entitlement_id: ee.entitlement.id,
            entitlement_name: ee.entitlement.name,
            application_id: ee.entitlement.application_id,
            risk_level: format!("{:?}", ee.entitlement.risk_level).to_lowercase(),
            sources: ee.sources.into_iter().map(Into::into).collect(),
        }
    }
}

/// Response for effective access query.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveAccessResponse {
    /// User ID.
    pub user_id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// All effective entitlements with their sources.
    pub entitlements: Vec<EffectiveEntitlementResponse>,

    /// Total count of unique entitlements.
    pub total: i64,
}

impl From<EffectiveAccessResult> for EffectiveAccessResponse {
    fn from(result: EffectiveAccessResult) -> Self {
        Self {
            user_id: result.user_id,
            tenant_id: result.tenant_id,
            entitlements: result.entitlements.into_iter().map(Into::into).collect(),
            total: result.total,
        }
    }
}
