//! Unified NHI API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::nhi::{
    AutoSuspendResponse, CampaignListResponse, CampaignResponse, CertifyResponse,
    CreateCampaignRequest, CreateSodRuleRequest, GracePeriodRequest, GracePeriodResponse,
    GrantPermissionRequest, InactiveDetectResponse, LifecycleActionResponse, NhiIdentityResponse,
    NhiListResponse, OrphanDetectResponse, PermissionListResponse, PermissionResponse,
    RevokeCertResponse, RevokePermissionResponse, RiskResponse, RiskSummaryResponse,
    SodCheckRequest, SodCheckResponse, SodRuleListResponse, SodRuleResponse, SuspendRequest,
    UpdateToolRequest,
};
use crate::models::tool::ToolResponse;
use uuid::Uuid;

impl ApiClient {
    // --- Unified List/Get ---

    /// List all NHI identities with optional filters
    pub async fn list_nhi(
        &self,
        limit: i32,
        offset: i32,
        nhi_type: Option<&str>,
        state: Option<&str>,
        owner: Option<Uuid>,
    ) -> CliResult<NhiListResponse> {
        let mut url = format!(
            "{}/nhi?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );
        if let Some(t) = nhi_type {
            url.push_str(&format!("&type={t}"));
        }
        if let Some(s) = state {
            url.push_str(&format!("&state={s}"));
        }
        if let Some(o) = owner {
            url.push_str(&format!("&owner={o}"));
        }

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

    /// Get a single NHI identity by ID
    pub async fn get_nhi(&self, id: Uuid) -> CliResult<NhiIdentityResponse> {
        let url = format!("{}/nhi/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("NHI identity not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Lifecycle Actions ---

    /// Suspend an NHI identity
    pub async fn nhi_suspend(
        &self,
        id: Uuid,
        request: SuspendRequest,
    ) -> CliResult<LifecycleActionResponse> {
        let url = format!("{}/nhi/{}/suspend", self.config().api_url, id);
        let response = self.post_json(&url, &request).await?;
        self.parse_lifecycle_response(response, id).await
    }

    /// Reactivate an NHI identity
    pub async fn nhi_reactivate(&self, id: Uuid) -> CliResult<LifecycleActionResponse> {
        let url = format!("{}/nhi/{}/reactivate", self.config().api_url, id);
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        self.parse_lifecycle_response(response, id).await
    }

    /// Deprecate an NHI identity
    pub async fn nhi_deprecate(&self, id: Uuid) -> CliResult<LifecycleActionResponse> {
        let url = format!("{}/nhi/{}/deprecate", self.config().api_url, id);
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        self.parse_lifecycle_response(response, id).await
    }

    /// Archive an NHI identity
    pub async fn nhi_archive(&self, id: Uuid) -> CliResult<LifecycleActionResponse> {
        let url = format!("{}/nhi/{}/archive", self.config().api_url, id);
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        self.parse_lifecycle_response(response, id).await
    }

    /// Deactivate an NHI identity
    pub async fn nhi_deactivate(&self, id: Uuid) -> CliResult<LifecycleActionResponse> {
        let url = format!("{}/nhi/{}/deactivate", self.config().api_url, id);
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        self.parse_lifecycle_response(response, id).await
    }

    /// Activate an NHI identity
    pub async fn nhi_activate(&self, id: Uuid) -> CliResult<LifecycleActionResponse> {
        let url = format!("{}/nhi/{}/activate", self.config().api_url, id);
        let response = self.post_json(&url, &serde_json::json!({})).await?;
        self.parse_lifecycle_response(response, id).await
    }

    async fn parse_lifecycle_response(
        &self,
        response: reqwest::Response,
        id: Uuid,
    ) -> CliResult<LifecycleActionResponse> {
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("NHI identity not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    // --- Permissions ---

    /// Grant a tool permission to an agent
    pub async fn nhi_grant_permission(
        &self,
        agent_id: Uuid,
        tool_id: Uuid,
        request: GrantPermissionRequest,
    ) -> CliResult<PermissionResponse> {
        let url = format!(
            "{}/nhi/agents/{}/tools/{}/grant",
            self.config().api_url,
            agent_id,
            tool_id
        );
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

    /// Revoke a tool permission from an agent
    pub async fn nhi_revoke_permission(
        &self,
        agent_id: Uuid,
        tool_id: Uuid,
    ) -> CliResult<RevokePermissionResponse> {
        let url = format!(
            "{}/nhi/agents/{}/tools/{}/revoke",
            self.config().api_url,
            agent_id,
            tool_id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;

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

    /// List tools an agent has permission to use
    pub async fn nhi_list_agent_tools(&self, agent_id: Uuid) -> CliResult<PermissionListResponse> {
        let url = format!("{}/nhi/agents/{}/tools", self.config().api_url, agent_id);
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

    /// List agents that have permission to a tool
    pub async fn nhi_list_tool_agents(&self, tool_id: Uuid) -> CliResult<PermissionListResponse> {
        let url = format!("{}/nhi/tools/{}/agents", self.config().api_url, tool_id);
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

    /// Get risk assessment for an NHI identity
    pub async fn nhi_risk(&self, id: Uuid) -> CliResult<RiskResponse> {
        let url = format!("{}/nhi/{}/risk", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("NHI identity not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get tenant-wide risk summary
    pub async fn nhi_risk_summary(&self) -> CliResult<RiskSummaryResponse> {
        let url = format!("{}/nhi/risk-summary", self.config().api_url);
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

    // --- Certifications ---

    /// Create a certification campaign
    pub async fn nhi_create_campaign(
        &self,
        request: CreateCampaignRequest,
    ) -> CliResult<CampaignResponse> {
        let url = format!("{}/nhi/certifications", self.config().api_url);
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

    /// List certification campaigns
    pub async fn nhi_list_campaigns(
        &self,
        status_filter: Option<&str>,
    ) -> CliResult<CampaignListResponse> {
        let mut url = format!("{}/nhi/certifications", self.config().api_url);
        if let Some(s) = status_filter {
            url.push_str(&format!("?status={s}"));
        }

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

    /// Certify an NHI identity in a campaign
    pub async fn nhi_certify(&self, campaign_id: Uuid, nhi_id: Uuid) -> CliResult<CertifyResponse> {
        let url = format!(
            "{}/nhi/certifications/{}/certify/{}",
            self.config().api_url,
            campaign_id,
            nhi_id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;

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

    /// Revoke certification for an NHI identity in a campaign
    pub async fn nhi_revoke_cert(
        &self,
        campaign_id: Uuid,
        nhi_id: Uuid,
    ) -> CliResult<RevokeCertResponse> {
        let url = format!(
            "{}/nhi/certifications/{}/revoke/{}",
            self.config().api_url,
            campaign_id,
            nhi_id
        );
        let response = self.post_json(&url, &serde_json::json!({})).await?;

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

    // --- SoD (Separation of Duties) ---

    /// Create a SoD rule
    pub async fn nhi_create_sod_rule(
        &self,
        request: CreateSodRuleRequest,
    ) -> CliResult<SodRuleResponse> {
        let url = format!("{}/nhi/sod/rules", self.config().api_url);
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

    /// List SoD rules
    pub async fn nhi_list_sod_rules(&self) -> CliResult<SodRuleListResponse> {
        let url = format!("{}/nhi/sod/rules", self.config().api_url);
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

    /// Delete a SoD rule
    pub async fn nhi_delete_sod_rule(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/nhi/sod/rules/{}", self.config().api_url, id);
        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
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

    /// Check SoD for an agent-tool combination
    pub async fn nhi_sod_check(&self, request: SodCheckRequest) -> CliResult<SodCheckResponse> {
        let url = format!("{}/nhi/sod/check", self.config().api_url);
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

    // --- Inactivity ---

    /// Detect inactive NHI identities
    pub async fn nhi_detect_inactive(&self) -> CliResult<InactiveDetectResponse> {
        let url = format!("{}/nhi/inactivity/detect", self.config().api_url);
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

    /// Auto-suspend inactive NHI identities
    pub async fn nhi_auto_suspend(&self) -> CliResult<AutoSuspendResponse> {
        let url = format!("{}/nhi/inactivity/auto-suspend", self.config().api_url);
        let response = self.post_json(&url, &serde_json::json!({})).await?;

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

    /// Set grace period for an NHI identity before auto-suspend
    pub async fn nhi_grace_period(
        &self,
        id: Uuid,
        request: GracePeriodRequest,
    ) -> CliResult<GracePeriodResponse> {
        let url = format!(
            "{}/nhi/inactivity/grace-period/{}",
            self.config().api_url,
            id
        );
        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("NHI identity not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Detect orphaned NHI identities
    pub async fn nhi_detect_orphans(&self) -> CliResult<OrphanDetectResponse> {
        let url = format!("{}/nhi/orphans/detect", self.config().api_url);
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

    // --- Tool Update ---

    /// Update a tool via PATCH
    pub async fn update_tool(
        &self,
        id: Uuid,
        request: UpdateToolRequest,
    ) -> CliResult<ToolResponse> {
        let url = format!("{}/nhi/tools/{}", self.config().api_url, id);
        let response = self.patch_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Tool not found: {id}")))
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
