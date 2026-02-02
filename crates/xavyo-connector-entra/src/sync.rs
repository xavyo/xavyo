//! User synchronization from Entra ID.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

use crate::{EntraConnector, EntraError, EntraResult};

/// User fields to select from Graph API.
const USER_SELECT_FIELDS: &str = "id,userPrincipalName,mail,displayName,givenName,surname,\
    department,jobTitle,employeeId,accountEnabled,createdDateTime,signInActivity";

/// Mapped Entra user with normalized fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedEntraUser {
    /// Entra object ID.
    pub external_id: String,
    /// User principal name (usually email format).
    pub user_principal_name: String,
    /// Primary email address.
    pub email: Option<String>,
    /// Display name.
    pub display_name: String,
    /// Given (first) name.
    pub given_name: Option<String>,
    /// Surname (last name).
    pub surname: Option<String>,
    /// Department.
    pub department: Option<String>,
    /// Job title.
    pub job_title: Option<String>,
    /// Employee ID.
    pub employee_id: Option<String>,
    /// Manager's Entra object ID.
    pub manager_id: Option<String>,
    /// Whether the account is enabled.
    pub account_enabled: bool,
    /// Account creation timestamp.
    pub created_at: Option<DateTime<Utc>>,
    /// Last sign-in timestamp.
    pub last_sign_in: Option<DateTime<Utc>>,
}

impl MappedEntraUser {
    /// Parses a user from the Graph API JSON response.
    pub fn from_json(value: &serde_json::Value) -> EntraResult<Self> {
        Ok(Self {
            external_id: value
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| EntraError::Sync("Missing user id".into()))?
                .to_string(),
            user_principal_name: value
                .get("userPrincipalName")
                .and_then(|v| v.as_str())
                .ok_or_else(|| EntraError::Sync("Missing userPrincipalName".into()))?
                .to_string(),
            email: value.get("mail").and_then(|v| v.as_str()).map(String::from),
            display_name: value
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            given_name: value
                .get("givenName")
                .and_then(|v| v.as_str())
                .map(String::from),
            surname: value
                .get("surname")
                .and_then(|v| v.as_str())
                .map(String::from),
            department: value
                .get("department")
                .and_then(|v| v.as_str())
                .map(String::from),
            job_title: value
                .get("jobTitle")
                .and_then(|v| v.as_str())
                .map(String::from),
            employee_id: value
                .get("employeeId")
                .and_then(|v| v.as_str())
                .map(String::from),
            manager_id: value
                .get("manager")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .map(String::from),
            account_enabled: value
                .get("accountEnabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            created_at: value
                .get("createdDateTime")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            last_sign_in: value
                .get("signInActivity")
                .and_then(|v| v.get("lastSignInDateTime"))
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
        })
    }
}

/// User sync result.
#[derive(Debug, Clone)]
pub struct UserSyncResult {
    /// Users that were synced.
    pub users: Vec<MappedEntraUser>,
    /// Users that were deleted (for delta sync).
    pub deleted_ids: Vec<String>,
    /// Delta link for next incremental sync.
    pub delta_link: Option<String>,
    /// Whether this was a full sync.
    pub is_full_sync: bool,
}

impl EntraConnector {
    /// Builds the user query URL with configured filters.
    fn build_user_query_url(&self) -> String {
        let mut url = format!(
            "{}/users?$select={}&$top={}&$expand=manager($select=id)",
            self.graph_client().base_url(),
            USER_SELECT_FIELDS,
            self.config().page_size
        );

        if let Some(ref filter) = self.config().user_filter {
            url.push_str(&format!("&$filter={}", urlencoding::encode(filter)));
        }

        url
    }

    /// Performs a full user sync.
    #[instrument(skip(self))]
    pub async fn full_user_sync(&self) -> EntraResult<UserSyncResult> {
        info!("Starting full user sync");

        let url = self.build_user_query_url();
        let mut all_users = Vec::new();

        let delta_link = self
            .graph_client()
            .get_paginated(&url, |page: Vec<serde_json::Value>| {
                debug!("Processing page with {} users", page.len());
                for value in page {
                    match MappedEntraUser::from_json(&value) {
                        Ok(user) => all_users.push(user),
                        Err(e) => {
                            tracing::warn!("Failed to parse user: {}", e);
                        }
                    }
                }
                Ok(())
            })
            .await?;

        info!("Full sync completed, {} users synced", all_users.len());

        Ok(UserSyncResult {
            users: all_users,
            deleted_ids: Vec::new(),
            delta_link,
            is_full_sync: true,
        })
    }

    /// Performs a delta (incremental) user sync.
    #[instrument(skip(self))]
    pub async fn delta_user_sync(&self) -> EntraResult<UserSyncResult> {
        let delta_link = match &self.config().delta_link_user {
            Some(link) => link.clone(),
            None => {
                info!("No delta link available, performing full sync");
                return self.full_user_sync().await;
            }
        };

        info!("Starting delta user sync");

        let mut all_users = Vec::new();
        let mut deleted_ids = Vec::new();

        let new_delta_link = self
            .graph_client()
            .get_paginated(&delta_link, |page: Vec<serde_json::Value>| {
                debug!("Processing delta page with {} items", page.len());
                for value in page {
                    // Check if this is a deleted user
                    if let Some(removed) = value.get("@removed") {
                        if let Some(reason) = removed.get("reason").and_then(|v| v.as_str()) {
                            if reason == "deleted" || reason == "changed" {
                                if let Some(id) = value.get("id").and_then(|v| v.as_str()) {
                                    deleted_ids.push(id.to_string());
                                }
                            }
                        }
                        continue;
                    }

                    // Parse as regular user
                    match MappedEntraUser::from_json(&value) {
                        Ok(user) => all_users.push(user),
                        Err(e) => {
                            tracing::warn!("Failed to parse user in delta: {}", e);
                        }
                    }
                }
                Ok(())
            })
            .await
            .map_err(|e| {
                // Check if delta token expired
                if let EntraError::GraphApi { ref code, .. } = e {
                    if code.contains("resyncRequired") || code.contains("syncStateNotFound") {
                        return EntraError::DeltaTokenExpired;
                    }
                }
                e
            })?;

        info!(
            "Delta sync completed, {} users updated, {} deleted",
            all_users.len(),
            deleted_ids.len()
        );

        Ok(UserSyncResult {
            users: all_users,
            deleted_ids,
            delta_link: new_delta_link,
            is_full_sync: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapped_user_from_json_complete() {
        let json = serde_json::json!({
            "id": "user-123",
            "userPrincipalName": "john.doe@example.com",
            "mail": "john.doe@example.com",
            "displayName": "John Doe",
            "givenName": "John",
            "surname": "Doe",
            "department": "Engineering",
            "jobTitle": "Software Engineer",
            "employeeId": "EMP001",
            "accountEnabled": true,
            "createdDateTime": "2024-01-15T10:00:00Z",
            "manager": {
                "id": "manager-456"
            }
        });

        let user = MappedEntraUser::from_json(&json).unwrap();
        assert_eq!(user.external_id, "user-123");
        assert_eq!(user.user_principal_name, "john.doe@example.com");
        assert_eq!(user.display_name, "John Doe");
        assert_eq!(user.department, Some("Engineering".to_string()));
        assert_eq!(user.manager_id, Some("manager-456".to_string()));
        assert!(user.account_enabled);
    }

    #[test]
    fn test_mapped_user_from_json_minimal() {
        let json = serde_json::json!({
            "id": "user-123",
            "userPrincipalName": "john@example.com"
        });

        let user = MappedEntraUser::from_json(&json).unwrap();
        assert_eq!(user.external_id, "user-123");
        assert_eq!(user.user_principal_name, "john@example.com");
        assert!(user.email.is_none());
        assert!(user.department.is_none());
    }

    #[test]
    fn test_mapped_user_disabled_account() {
        let json = serde_json::json!({
            "id": "user-123",
            "userPrincipalName": "disabled@example.com",
            "accountEnabled": false
        });

        let user = MappedEntraUser::from_json(&json).unwrap();
        assert!(!user.account_enabled);
    }
}
