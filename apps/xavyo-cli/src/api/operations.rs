//! Operations and jobs API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::operation::{
    DlqListResponse, JobListResponse, JobResponse, OperationListResponse, OperationResponse,
    QueueStatsResponse,
};
use uuid::Uuid;

impl ApiClient {
    /// List provisioning operations
    pub async fn list_prov_operations(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<OperationListResponse> {
        let url = format!(
            "{}/operations?limit={}&offset={}",
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

    /// Get a single operation
    pub async fn get_prov_operation(&self, id: Uuid) -> CliResult<OperationResponse> {
        let url = format!("{}/operations/{}", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Operation not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get operation queue stats
    pub async fn get_queue_stats(&self) -> CliResult<QueueStatsResponse> {
        let url = format!("{}/operations/stats", self.config().api_url);
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

    /// Retry a failed operation
    pub async fn retry_prov_operation(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/operations/{}/retry", self.config().api_url, id);
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

    /// Cancel a pending operation
    pub async fn cancel_prov_operation(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/operations/{}/cancel", self.config().api_url, id);
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

    /// List connector jobs
    pub async fn list_jobs(&self, limit: i32, offset: i32) -> CliResult<JobListResponse> {
        let url = format!(
            "{}/connectors/jobs?limit={}&offset={}",
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

    /// Get a single job
    pub async fn get_job(&self, id: Uuid) -> CliResult<JobResponse> {
        let url = format!("{}/connectors/jobs/{}", self.config().api_url, id);
        let response = self.get_authenticated(&url).await?;
        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Job not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Cancel a job
    pub async fn cancel_job(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/connectors/jobs/{}/cancel", self.config().api_url, id);
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

    /// List dead letter queue entries
    pub async fn list_dlq(&self, limit: i32, offset: i32) -> CliResult<DlqListResponse> {
        let url = format!(
            "{}/connectors/dlq?limit={}&offset={}",
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

    /// Replay a DLQ entry
    pub async fn replay_dlq(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/connectors/dlq/{}/replay", self.config().api_url, id);
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
}
