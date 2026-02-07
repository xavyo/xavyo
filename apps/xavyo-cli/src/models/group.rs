//! Group data models for the CLI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Group response from the API
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupResponse {
    pub id: Uuid,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub group_type: Option<String>,
    #[serde(default)]
    pub member_count: Option<i64>,
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Group list response
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupListResponse {
    pub groups: Vec<GroupResponse>,
    #[serde(default)]
    pub pagination: Option<crate::models::user::PaginationInfo>,
}
