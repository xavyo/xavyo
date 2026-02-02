//! Directory roles and license synchronization from Entra ID.

use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::{EntraConnector, EntraResult};

/// Entra directory role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraDirectoryRole {
    /// Role ID.
    pub id: String,
    /// Role template ID.
    pub role_template_id: Option<String>,
    /// Display name.
    pub display_name: String,
    /// Description.
    pub description: Option<String>,
}

/// Entra license (subscription SKU).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraLicense {
    /// SKU ID.
    pub sku_id: String,
    /// SKU part number.
    pub sku_part_number: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Consumed units.
    pub consumed_units: i64,
    /// Prepaid units (enabled).
    pub enabled_units: i64,
}

/// User's assigned licenses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLicenses {
    /// User ID.
    pub user_id: String,
    /// Assigned license SKU IDs.
    pub license_sku_ids: Vec<String>,
}

impl EntraConnector {
    /// Lists all activated directory roles in the tenant.
    #[instrument(skip(self))]
    pub async fn list_directory_roles(&self) -> EntraResult<Vec<EntraDirectoryRole>> {
        if !self.config().sync_directory_roles {
            return Ok(Vec::new());
        }

        info!("Fetching directory roles");

        let url = format!(
            "{}/directoryRoles?$select=id,roleTemplateId,displayName,description",
            self.graph_client().base_url()
        );

        let mut roles = Vec::new();

        self.graph_client()
            .get_paginated(&url, |page: Vec<serde_json::Value>| {
                for value in page {
                    if let (Some(id), Some(display_name)) = (
                        value.get("id").and_then(|v| v.as_str()),
                        value.get("displayName").and_then(|v| v.as_str()),
                    ) {
                        roles.push(EntraDirectoryRole {
                            id: id.to_string(),
                            role_template_id: value
                                .get("roleTemplateId")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            display_name: display_name.to_string(),
                            description: value
                                .get("description")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                        });
                    }
                }
                Ok(())
            })
            .await?;

        info!("Found {} directory roles", roles.len());

        Ok(roles)
    }

    /// Lists members of a directory role.
    #[instrument(skip(self))]
    pub async fn list_role_members(&self, role_id: &str) -> EntraResult<Vec<String>> {
        let url = format!(
            "{}/directoryRoles/{}/members?$select=id",
            self.graph_client().base_url(),
            role_id
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

    /// Lists subscribed SKUs (licenses) in the tenant.
    #[instrument(skip(self))]
    pub async fn list_subscribed_skus(&self) -> EntraResult<Vec<EntraLicense>> {
        if !self.config().sync_licenses {
            return Ok(Vec::new());
        }

        info!("Fetching subscribed SKUs");

        let url = format!(
            "{}/subscribedSkus?$select=skuId,skuPartNumber,consumedUnits,prepaidUnits",
            self.graph_client().base_url()
        );

        #[derive(Deserialize)]
        struct SkuResponse {
            value: Vec<serde_json::Value>,
        }

        let response: SkuResponse = self.graph_client().get(&url).await?;

        let licenses: Vec<EntraLicense> = response
            .value
            .into_iter()
            .filter_map(|v| {
                Some(EntraLicense {
                    sku_id: v.get("skuId")?.as_str()?.to_string(),
                    sku_part_number: v.get("skuPartNumber")?.as_str()?.to_string(),
                    display_name: None, // Not available in API response
                    consumed_units: v.get("consumedUnits")?.as_i64()?,
                    enabled_units: v
                        .get("prepaidUnits")
                        .and_then(|pu| pu.get("enabled"))
                        .and_then(|e| e.as_i64())
                        .unwrap_or(0),
                })
            })
            .collect();

        info!("Found {} subscribed SKUs", licenses.len());

        Ok(licenses)
    }

    /// Gets licenses assigned to a specific user.
    #[instrument(skip(self))]
    pub async fn get_user_licenses(&self, user_id: &str) -> EntraResult<UserLicenses> {
        let url = format!(
            "{}/users/{}/licenseDetails?$select=skuId",
            self.graph_client().base_url(),
            user_id
        );

        #[derive(Deserialize)]
        struct LicenseResponse {
            value: Vec<serde_json::Value>,
        }

        let response: LicenseResponse = self.graph_client().get(&url).await?;

        let sku_ids: Vec<String> = response
            .value
            .into_iter()
            .filter_map(|v| v.get("skuId")?.as_str().map(String::from))
            .collect();

        Ok(UserLicenses {
            user_id: user_id.to_string(),
            license_sku_ids: sku_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_role_struct() {
        let role = EntraDirectoryRole {
            id: "role-123".to_string(),
            role_template_id: Some("template-456".to_string()),
            display_name: "Global Administrator".to_string(),
            description: Some("Can manage all aspects".to_string()),
        };

        assert_eq!(role.display_name, "Global Administrator");
    }

    #[test]
    fn test_license_struct() {
        let license = EntraLicense {
            sku_id: "sku-123".to_string(),
            sku_part_number: "ENTERPRISEPACK".to_string(),
            display_name: Some("Office 365 E3".to_string()),
            consumed_units: 50,
            enabled_units: 100,
        };

        assert_eq!(license.sku_part_number, "ENTERPRISEPACK");
        assert_eq!(license.consumed_units, 50);
    }
}
