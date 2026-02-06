//! User API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::user::{CreateUserRequest, UpdateUserRequest, UserListResponse, UserResponse};
use uuid::Uuid;

impl ApiClient {
    /// List users for the current tenant
    pub async fn list_users(&self, limit: i32, offset: i32) -> CliResult<UserListResponse> {
        let url = format!(
            "{}/admin/users?limit={}&offset={}",
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

    /// Get a single user by ID
    pub async fn get_user(&self, id: Uuid) -> CliResult<UserResponse> {
        let url = format!("{}/admin/users/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("User not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Create a new user
    pub async fn create_user(&self, request: CreateUserRequest) -> CliResult<UserResponse> {
        let url = format!("{}/admin/users", self.config().api_url);

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::CONFLICT {
            Err(CliError::Conflict(format!(
                "User already exists: {}",
                request.email
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

    /// Update a user
    pub async fn update_user(
        &self,
        id: Uuid,
        request: UpdateUserRequest,
    ) -> CliResult<UserResponse> {
        let url = format!("{}/admin/users/{}", self.config().api_url, id);

        let response = self.put_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("User not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Delete (deactivate) a user
    pub async fn delete_user(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/admin/users/{}", self.config().api_url, id);

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("User not found: {id}")))
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
