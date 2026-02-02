//! Group synchronization from Entra ID.

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

use crate::{EntraConnector, EntraError, EntraResult};

/// Group type classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntraGroupType {
    /// Security group.
    Security,
    /// Microsoft 365 group.
    Microsoft365,
    /// Distribution list.
    Distribution,
    /// Mail-enabled security group.
    MailEnabledSecurity,
    /// Unknown group type.
    Unknown,
}

/// Mapped Entra group with normalized fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedEntraGroup {
    /// Entra object ID.
    pub external_id: String,
    /// Group display name.
    pub display_name: String,
    /// Group description.
    pub description: Option<String>,
    /// Group email address (if mail-enabled).
    pub mail: Option<String>,
    /// Group type.
    pub group_type: EntraGroupType,
    /// Whether this is a dynamic membership group.
    pub is_dynamic: bool,
    /// Member IDs (user object IDs).
    pub members: Vec<String>,
}

impl MappedEntraGroup {
    /// Parses a group from the Graph API JSON response.
    pub fn from_json(value: &serde_json::Value) -> EntraResult<Self> {
        let group_types = value
            .get("groupTypes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let security_enabled = value
            .get("securityEnabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mail_enabled = value
            .get("mailEnabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let is_dynamic = group_types.contains(&"DynamicMembership".to_string());

        let group_type = Self::derive_group_type(&group_types, security_enabled, mail_enabled);

        Ok(Self {
            external_id: value
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| EntraError::Sync("Missing group id".into()))?
                .to_string(),
            display_name: value
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            description: value
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from),
            mail: value.get("mail").and_then(|v| v.as_str()).map(String::from),
            group_type,
            is_dynamic,
            members: Vec::new(), // Members loaded separately
        })
    }

    /// Derives the group type from Graph API properties.
    fn derive_group_type(
        group_types: &[String],
        security_enabled: bool,
        mail_enabled: bool,
    ) -> EntraGroupType {
        if group_types.contains(&"Unified".to_string()) {
            EntraGroupType::Microsoft365
        } else if security_enabled && mail_enabled {
            EntraGroupType::MailEnabledSecurity
        } else if security_enabled {
            EntraGroupType::Security
        } else if mail_enabled {
            EntraGroupType::Distribution
        } else {
            EntraGroupType::Unknown
        }
    }
}

/// Group sync result.
#[derive(Debug, Clone)]
pub struct GroupSyncResult {
    /// Groups that were synced.
    pub groups: Vec<MappedEntraGroup>,
    /// Groups that were deleted (for delta sync).
    pub deleted_ids: Vec<String>,
    /// Delta link for next incremental sync.
    pub delta_link: Option<String>,
    /// Whether this was a full sync.
    pub is_full_sync: bool,
}

impl EntraConnector {
    /// Builds the group query URL with configured filters.
    fn build_group_query_url(&self) -> String {
        let mut url = format!(
            "{}/groups?$select=id,displayName,description,mail,groupTypes,securityEnabled,mailEnabled&$top={}",
            self.graph_client().base_url(),
            self.config().page_size
        );

        if let Some(ref filter) = self.config().group_filter {
            url.push_str(&format!("&$filter={}", urlencoding::encode(filter)));
        }

        url
    }

    /// Fetches members for a group.
    #[instrument(skip(self))]
    pub async fn fetch_group_members(&self, group_id: &str) -> EntraResult<Vec<String>> {
        let endpoint = if self.config().resolve_transitive_members {
            "transitiveMembers"
        } else {
            "members"
        };

        let url = format!(
            "{}/groups/{}/{}?$select=id&$top={}",
            self.graph_client().base_url(),
            group_id,
            endpoint,
            self.config().page_size
        );

        let mut member_ids = Vec::new();

        self.graph_client()
            .get_paginated(&url, |page: Vec<serde_json::Value>| {
                for value in page {
                    if let Some(id) = value.get("id").and_then(|v| v.as_str()) {
                        member_ids.push(id.to_string());
                    }
                }
                Ok(())
            })
            .await?;

        Ok(member_ids)
    }

    /// Performs a full group sync.
    #[instrument(skip(self))]
    pub async fn full_group_sync(&self) -> EntraResult<GroupSyncResult> {
        if !self.config().sync_groups {
            return Ok(GroupSyncResult {
                groups: Vec::new(),
                deleted_ids: Vec::new(),
                delta_link: None,
                is_full_sync: true,
            });
        }

        info!("Starting full group sync");

        let url = self.build_group_query_url();
        let mut all_groups = Vec::new();

        let delta_link = self
            .graph_client()
            .get_paginated(&url, |page: Vec<serde_json::Value>| {
                debug!("Processing page with {} groups", page.len());
                for value in page {
                    match MappedEntraGroup::from_json(&value) {
                        Ok(group) => all_groups.push(group),
                        Err(e) => {
                            tracing::warn!("Failed to parse group: {}", e);
                        }
                    }
                }
                Ok(())
            })
            .await?;

        // Fetch members for each group
        for group in &mut all_groups {
            match self.fetch_group_members(&group.external_id).await {
                Ok(members) => group.members = members,
                Err(e) => {
                    tracing::warn!(
                        "Failed to fetch members for group {}: {}",
                        group.external_id,
                        e
                    );
                }
            }
        }

        info!(
            "Full group sync completed, {} groups synced",
            all_groups.len()
        );

        Ok(GroupSyncResult {
            groups: all_groups,
            deleted_ids: Vec::new(),
            delta_link,
            is_full_sync: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_type_security() {
        let json = serde_json::json!({
            "id": "group-123",
            "displayName": "Security Group",
            "groupTypes": [],
            "securityEnabled": true,
            "mailEnabled": false
        });

        let group = MappedEntraGroup::from_json(&json).unwrap();
        assert_eq!(group.group_type, EntraGroupType::Security);
        assert!(!group.is_dynamic);
    }

    #[test]
    fn test_group_type_m365() {
        let json = serde_json::json!({
            "id": "group-123",
            "displayName": "M365 Group",
            "groupTypes": ["Unified"],
            "securityEnabled": false,
            "mailEnabled": true,
            "mail": "group@example.com"
        });

        let group = MappedEntraGroup::from_json(&json).unwrap();
        assert_eq!(group.group_type, EntraGroupType::Microsoft365);
        assert_eq!(group.mail, Some("group@example.com".to_string()));
    }

    #[test]
    fn test_group_type_dynamic() {
        let json = serde_json::json!({
            "id": "group-123",
            "displayName": "Dynamic Group",
            "groupTypes": ["DynamicMembership"],
            "securityEnabled": true,
            "mailEnabled": false
        });

        let group = MappedEntraGroup::from_json(&json).unwrap();
        assert_eq!(group.group_type, EntraGroupType::Security);
        assert!(group.is_dynamic);
    }
}
