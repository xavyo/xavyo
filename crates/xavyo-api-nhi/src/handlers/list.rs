//! Handler for listing Non-Human Identities.
//!
//! Provides `GET /nhi` endpoint with filtering and pagination.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{NhiViewFilter, NonHumanIdentityView};

use crate::services::unified_list_service::UnifiedListService;

/// Query parameters for listing NHIs.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct NhiListQuery {
    /// Filter by NHI type: "`service_account`", "`ai_agent`", or omit for all.
    #[serde(rename = "type")]
    pub nhi_type: Option<String>,

    /// Filter by status: "active", "suspended", "expired", etc.
    pub status: Option<String>,

    /// Filter by owner user ID.
    pub owner_id: Option<Uuid>,

    /// Filter by minimum risk score (0-100).
    pub risk_min: Option<i32>,

    /// Filter for NHIs with certification due within 30 days.
    #[serde(default)]
    pub certification_due: bool,

    /// Number of results per page (default: 20, max: 100).
    #[serde(default = "default_per_page")]
    pub per_page: i64,

    /// Page number (1-indexed, default: 1).
    #[serde(default = "default_page")]
    pub page: i64,
}

fn default_per_page() -> i64 {
    20
}

fn default_page() -> i64 {
    1
}

impl From<NhiListQuery> for NhiViewFilter {
    fn from(query: NhiListQuery) -> Self {
        NhiViewFilter {
            nhi_type: query.nhi_type,
            status: query.status,
            owner_id: query.owner_id,
            risk_min: query.risk_min,
            certification_due: query.certification_due,
        }
    }
}

/// Paginated response for NHI listing.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiListResponse {
    /// List of NHIs.
    pub items: Vec<NhiItem>,

    /// Total count of matching NHIs.
    pub total: i64,

    /// Current page number.
    pub page: i64,

    /// Items per page.
    pub per_page: i64,

    /// Total number of pages.
    pub total_pages: i64,
}

/// Individual NHI item in the listing.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiItem {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Display name.
    pub name: String,

    /// Description or purpose.
    pub description: Option<String>,

    /// Type discriminator: "`service_account`" or "`ai_agent`".
    pub nhi_type: String,

    /// Primary owner user ID.
    pub owner_id: Uuid,

    /// Backup owner user ID.
    pub backup_owner_id: Option<Uuid>,

    /// Current status.
    pub status: String,

    /// When the NHI was created.
    pub created_at: DateTime<Utc>,

    /// When the NHI expires.
    pub expires_at: Option<DateTime<Utc>>,

    /// Last activity timestamp.
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Risk score (0-100).
    pub risk_score: i32,

    /// Risk level category.
    pub risk_level: String,

    /// When next certification is due.
    pub next_certification_at: Option<DateTime<Utc>>,

    /// When last certified.
    pub last_certified_at: Option<DateTime<Utc>>,
}

impl From<NonHumanIdentityView> for NhiItem {
    fn from(nhi: NonHumanIdentityView) -> Self {
        let risk_level = nhi.risk_level().to_string();
        NhiItem {
            id: nhi.id,
            tenant_id: nhi.tenant_id,
            name: nhi.name,
            description: nhi.description,
            nhi_type: nhi.nhi_type,
            owner_id: nhi.owner_id,
            backup_owner_id: nhi.backup_owner_id,
            status: nhi.status,
            created_at: nhi.created_at,
            expires_at: nhi.expires_at,
            last_activity_at: nhi.last_activity_at,
            risk_score: nhi.risk_score,
            risk_level,
            next_certification_at: nhi.next_certification_at,
            last_certified_at: nhi.last_certified_at,
        }
    }
}

/// Application state for NHI handlers.
#[derive(Clone)]
pub struct NhiState {
    pub list_service: UnifiedListService,
}

/// Handler for `GET /nhi`.
///
/// Lists all non-human identities (service accounts and AI agents) with
/// optional filtering by type, status, owner, risk score, and certification status.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi",
    tag = "nhi",
    params(NhiListQuery),
    responses(
        (status = 200, description = "List of NHIs", body = NhiListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
))]
pub async fn list_nhi(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<NhiState>,
    Query(query): Query<NhiListQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Validate pagination parameters
    let per_page = query.per_page.clamp(1, 100);
    let page = query.page.max(1);
    let offset = (page - 1) * per_page;

    let filter: NhiViewFilter = query.into();

    // Get total count
    let total = state
        .list_service
        .count(tenant_id, filter.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to count NHIs: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    // Get paginated items
    let items = state
        .list_service
        .list(tenant_id, filter, per_page, offset)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list NHIs: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    let total_pages = (total as f64 / per_page as f64).ceil() as i64;

    let response = NhiListResponse {
        items: items.into_iter().map(NhiItem::from).collect(),
        total,
        page,
        per_page,
        total_pages,
    };

    Ok(Json(response))
}

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, (StatusCode, String)> {
    claims.tenant_id().map(|t| *t.as_uuid()).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Missing tenant ID in claims".to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_list_query_defaults() {
        let query = NhiListQuery {
            nhi_type: None,
            status: None,
            owner_id: None,
            risk_min: None,
            certification_due: false,
            per_page: default_per_page(),
            page: default_page(),
        };

        assert_eq!(query.per_page, 20);
        assert_eq!(query.page, 1);
    }

    #[test]
    fn test_nhi_list_query_to_filter() {
        let owner_id = Uuid::new_v4();
        let query = NhiListQuery {
            nhi_type: Some("service_account".to_string()),
            status: Some("active".to_string()),
            owner_id: Some(owner_id),
            risk_min: Some(50),
            certification_due: true,
            per_page: 10,
            page: 2,
        };

        let filter: NhiViewFilter = query.into();
        assert_eq!(filter.nhi_type, Some("service_account".to_string()));
        assert_eq!(filter.status, Some("active".to_string()));
        assert_eq!(filter.owner_id, Some(owner_id));
        assert_eq!(filter.risk_min, Some(50));
        assert!(filter.certification_due);
    }

    #[test]
    fn test_nhi_list_response_serialization() {
        let response = NhiListResponse {
            items: vec![],
            total: 0,
            page: 1,
            per_page: 20,
            total_pages: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"page\":1"));
    }

    // T034: Test status filtering
    #[test]
    fn test_nhi_list_query_status_filter() {
        // Test with status filter
        let query_active = NhiListQuery {
            nhi_type: None,
            status: Some("active".to_string()),
            owner_id: None,
            risk_min: None,
            certification_due: false,
            per_page: default_per_page(),
            page: default_page(),
        };

        let filter: NhiViewFilter = query_active.into();
        assert_eq!(filter.status, Some("active".to_string()));

        // Test with suspended status
        let query_suspended = NhiListQuery {
            nhi_type: None,
            status: Some("suspended".to_string()),
            owner_id: None,
            risk_min: None,
            certification_due: false,
            per_page: default_per_page(),
            page: default_page(),
        };

        let filter: NhiViewFilter = query_suspended.into();
        assert_eq!(filter.status, Some("suspended".to_string()));

        // Test with expired status
        let query_expired = NhiListQuery {
            nhi_type: None,
            status: Some("expired".to_string()),
            owner_id: None,
            risk_min: None,
            certification_due: false,
            per_page: default_per_page(),
            page: default_page(),
        };

        let filter: NhiViewFilter = query_expired.into();
        assert_eq!(filter.status, Some("expired".to_string()));

        // Test without status filter
        let query_no_status = NhiListQuery {
            nhi_type: None,
            status: None,
            owner_id: None,
            risk_min: None,
            certification_due: false,
            per_page: default_per_page(),
            page: default_page(),
        };

        let filter: NhiViewFilter = query_no_status.into();
        assert!(filter.status.is_none());
    }

    // T035: Test owner_id filtering
    #[test]
    fn test_nhi_list_query_owner_id_filter() {
        let owner_id = Uuid::new_v4();

        // Test with owner_id filter
        let query_with_owner = NhiListQuery {
            nhi_type: None,
            status: None,
            owner_id: Some(owner_id),
            risk_min: None,
            certification_due: false,
            per_page: default_per_page(),
            page: default_page(),
        };

        let filter: NhiViewFilter = query_with_owner.into();
        assert_eq!(filter.owner_id, Some(owner_id));

        // Test without owner_id filter
        let query_no_owner = NhiListQuery {
            nhi_type: None,
            status: None,
            owner_id: None,
            risk_min: None,
            certification_due: false,
            per_page: default_per_page(),
            page: default_page(),
        };

        let filter: NhiViewFilter = query_no_owner.into();
        assert!(filter.owner_id.is_none());

        // Test combining owner_id with other filters
        let another_owner_id = Uuid::new_v4();
        let query_combined = NhiListQuery {
            nhi_type: Some("ai_agent".to_string()),
            status: Some("active".to_string()),
            owner_id: Some(another_owner_id),
            risk_min: Some(25),
            certification_due: true,
            per_page: 50,
            page: 3,
        };

        let filter: NhiViewFilter = query_combined.into();
        assert_eq!(filter.owner_id, Some(another_owner_id));
        assert_eq!(filter.nhi_type, Some("ai_agent".to_string()));
        assert_eq!(filter.status, Some("active".to_string()));
        assert_eq!(filter.risk_min, Some(25));
        assert!(filter.certification_due);
    }
}
