//! Governance API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::governance::{
    AccessRequestListResponse, AccessRequestResponse, CreateAccessRequest, EntitlementListResponse,
    EntitlementResponse, RoleListResponse, RoleResponse,
};
use uuid::Uuid;

impl ApiClient {
    // --- Roles ---

    /// List governance roles
    pub async fn list_roles(&self, limit: i32, offset: i32) -> CliResult<RoleListResponse> {
        let url = format!(
            "{}/governance/roles?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a single role
    pub async fn get_role(&self, id: Uuid) -> CliResult<RoleResponse> {
        let url = format!("{}/governance/roles/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Role not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Entitlements ---

    /// List entitlements
    pub async fn list_entitlements(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<EntitlementListResponse> {
        let url = format!(
            "{}/governance/entitlements?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a single entitlement
    pub async fn get_entitlement(&self, id: Uuid) -> CliResult<EntitlementResponse> {
        let url = format!("{}/governance/entitlements/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Entitlement not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Access Requests ---

    /// List access requests
    pub async fn list_access_requests(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<AccessRequestListResponse> {
        let url = format!(
            "{}/governance/access-requests?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a single access request
    pub async fn get_access_request(&self, id: Uuid) -> CliResult<AccessRequestResponse> {
        let url = format!(
            "{}/governance/access-requests/{}",
            self.config().api_url,
            id
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Access request not found: {id}"
            )))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Create a new access request
    pub async fn create_access_request(
        &self,
        request: CreateAccessRequest,
    ) -> CliResult<AccessRequestResponse> {
        let url = format!("{}/governance/access-requests", self.config().api_url);

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Cancel an access request
    pub async fn cancel_access_request(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/governance/access-requests/{}/cancel",
            self.config().api_url,
            id
        );

        let response = self.post_json(&url, &serde_json::json!({})).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Archetypes ---

    pub async fn list_archetypes(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::ArchetypeListResponse> {
        let url = format!(
            "{}/governance/archetypes?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_archetype(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::ArchetypeResponse> {
        let url = format!("{}/governance/archetypes/{}", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Archetype not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Lifecycle Configs ---

    pub async fn list_lifecycle_configs(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::LifecycleConfigListResponse> {
        let url = format!(
            "{}/governance/lifecycle/configs?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_lifecycle_config(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::LifecycleConfigResponse> {
        let url = format!(
            "{}/governance/lifecycle/configs/{}",
            self.config().api_url,
            id
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Lifecycle config not found: {id}"
            )))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- SoD Rules ---

    pub async fn list_sod_rules(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::SodRuleListResponse> {
        let url = format!(
            "{}/governance/sod-rules?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_sod_rule(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::SodRuleResponse> {
        let url = format!("{}/governance/sod-rules/{}", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("SoD rule not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn enable_sod_rule(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/governance/sod-rules/{}/enable",
            self.config().api_url,
            id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn disable_sod_rule(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/governance/sod-rules/{}/disable",
            self.config().api_url,
            id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn list_sod_violations(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::SodViolationListResponse> {
        let url = format!(
            "{}/governance/sod-violations?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Certification Campaigns ---

    pub async fn list_campaigns(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::CampaignListResponse> {
        let url = format!(
            "{}/governance/certification-campaigns?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_campaign(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::CampaignResponse> {
        let url = format!(
            "{}/governance/certification-campaigns/{}",
            self.config().api_url,
            id
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Campaign not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn launch_campaign(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/governance/certification-campaigns/{}/launch",
            self.config().api_url,
            id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn cancel_campaign(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/governance/certification-campaigns/{}/cancel",
            self.config().api_url,
            id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Object Templates ---

    pub async fn list_object_templates(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::ObjectTemplateListResponse> {
        let url = format!(
            "{}/governance/object-templates?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_object_template(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::ObjectTemplateResponse> {
        let url = format!(
            "{}/governance/object-templates/{}",
            self.config().api_url,
            id
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Object template not found: {id}"
            )))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Catalog ---

    pub async fn list_catalog_categories(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::CatalogCategoryListResponse> {
        let url = format!(
            "{}/governance/catalog/categories?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn list_catalog_items(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::CatalogItemListResponse> {
        let url = format!(
            "{}/governance/catalog/items?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_catalog_item(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::CatalogItemResponse> {
        let url = format!("{}/governance/catalog/items/{}", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Catalog item not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Bulk Actions ---

    pub async fn list_bulk_actions(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::BulkActionListResponse> {
        let url = format!(
            "{}/governance/admin/bulk-actions?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_bulk_action(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::BulkActionResponse> {
        let url = format!(
            "{}/governance/admin/bulk-actions/{}",
            self.config().api_url,
            id
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Bulk action not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Delegations ---

    pub async fn list_delegations(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::DelegationListResponse> {
        let url = format!(
            "{}/governance/delegations?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_delegation(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::DelegationResponse> {
        let url = format!("{}/governance/delegations/{}", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Delegation not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn revoke_delegation(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/governance/delegations/{}/revoke",
            self.config().api_url,
            id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- GDPR ---

    pub async fn get_gdpr_report(
        &self,
    ) -> CliResult<crate::models::governance::GdprReportResponse> {
        let url = format!("{}/governance/gdpr/report", self.config().api_url);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Risk ---

    pub async fn get_user_risk_score(
        &self,
        user_id: Uuid,
    ) -> CliResult<crate::models::governance::RiskScoreResponse> {
        let url = format!(
            "{}/governance/users/{}/risk-score",
            self.config().api_url,
            user_id
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Risk score not found for user: {user_id}"
            )))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn list_risk_alerts(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::RiskAlertListResponse> {
        let url = format!(
            "{}/governance/risk-alerts?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn acknowledge_risk_alert(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/governance/risk-alerts/{}/acknowledge",
            self.config().api_url,
            id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Reports ---

    pub async fn list_reports(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::ReportListResponse> {
        let url = format!(
            "{}/governance/reports?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_report(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::ReportResponse> {
        let url = format!("{}/governance/reports/{}", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Report not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Approval Workflows ---

    pub async fn list_approval_workflows(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<crate::models::governance::ApprovalWorkflowListResponse> {
        let url = format!(
            "{}/governance/approval-workflows?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    pub async fn get_approval_workflow(
        &self,
        id: Uuid,
    ) -> CliResult<crate::models::governance::ApprovalWorkflowResponse> {
        let url = format!(
            "{}/governance/approval-workflows/{}",
            self.config().api_url,
            id
        );
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Approval workflow not found: {id}"
            )))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }
}
