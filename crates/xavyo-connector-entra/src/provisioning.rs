//! Outbound provisioning to Entra ID.

use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::{EntraConnector, EntraResult};

/// Request to create a user in Entra ID.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    /// Whether the account is enabled.
    pub account_enabled: bool,
    /// Display name.
    pub display_name: String,
    /// User principal name (must be unique in tenant).
    pub user_principal_name: String,
    /// Mail nickname (username portion before @).
    pub mail_nickname: String,
    /// Password profile.
    pub password_profile: PasswordProfile,
    /// Given (first) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Surname (last name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surname: Option<String>,
    /// Job title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_title: Option<String>,
    /// Department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
}

/// Password profile for user creation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordProfile {
    /// The password.
    pub password: String,
    /// Whether the user must change password on next sign-in.
    pub force_change_password_next_sign_in: bool,
}

/// Request to update a user in Entra ID.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    /// Whether the account is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_enabled: Option<bool>,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Given (first) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Surname (last name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surname: Option<String>,
    /// Job title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_title: Option<String>,
    /// Department.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
}

/// Created user response.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatedUser {
    /// Entra object ID.
    pub id: String,
    /// User principal name.
    #[serde(rename = "userPrincipalName")]
    pub user_principal_name: String,
}

impl EntraConnector {
    /// Creates a user in Entra ID.
    #[instrument(skip(self, request))]
    pub async fn create_user(&self, request: &CreateUserRequest) -> EntraResult<CreatedUser> {
        info!("Creating user: {}", request.user_principal_name);

        let url = format!("{}/users", self.graph_client().base_url());

        let created: CreatedUser = self.graph_client().post(&url, request).await?;

        info!("User created with ID: {}", created.id);

        Ok(created)
    }

    /// Updates a user in Entra ID.
    #[instrument(skip(self, request))]
    pub async fn update_user(&self, user_id: &str, request: &UpdateUserRequest) -> EntraResult<()> {
        info!("Updating user: {}", user_id);

        let url = format!("{}/users/{}", self.graph_client().base_url(), user_id);

        // PATCH requests return 204 No Content, so we use a special response type
        let _: serde_json::Value = self.graph_client().patch(&url, request).await?;

        info!("User updated: {}", user_id);

        Ok(())
    }

    /// Disables a user in Entra ID.
    #[instrument(skip(self))]
    pub async fn disable_user(&self, user_id: &str) -> EntraResult<()> {
        info!("Disabling user: {}", user_id);

        let request = UpdateUserRequest {
            account_enabled: Some(false),
            ..Default::default()
        };

        self.update_user(user_id, &request).await
    }

    /// Enables a user in Entra ID.
    #[instrument(skip(self))]
    pub async fn enable_user(&self, user_id: &str) -> EntraResult<()> {
        info!("Enabling user: {}", user_id);

        let request = UpdateUserRequest {
            account_enabled: Some(true),
            ..Default::default()
        };

        self.update_user(user_id, &request).await
    }

    /// Deletes a user from Entra ID.
    #[instrument(skip(self))]
    pub async fn delete_user(&self, user_id: &str) -> EntraResult<()> {
        info!("Deleting user: {}", user_id);

        let url = format!("{}/users/{}", self.graph_client().base_url(), user_id);

        self.graph_client().delete(&url).await?;

        info!("User deleted: {}", user_id);

        Ok(())
    }

    /// Adds a user to a group.
    #[instrument(skip(self))]
    pub async fn add_user_to_group(&self, group_id: &str, user_id: &str) -> EntraResult<()> {
        info!("Adding user {} to group {}", user_id, group_id);

        let url = format!(
            "{}/groups/{}/members/$ref",
            self.graph_client().base_url(),
            group_id
        );

        let body = serde_json::json!({
            "@odata.id": format!("{}/directoryObjects/{}", self.graph_client().base_url(), user_id)
        });

        let _: serde_json::Value = self.graph_client().post(&url, &body).await?;

        info!("User added to group");

        Ok(())
    }

    /// Removes a user from a group.
    #[instrument(skip(self))]
    pub async fn remove_user_from_group(&self, group_id: &str, user_id: &str) -> EntraResult<()> {
        info!("Removing user {} from group {}", user_id, group_id);

        let url = format!(
            "{}/groups/{}/members/{}/$ref",
            self.graph_client().base_url(),
            group_id,
            user_id
        );

        self.graph_client().delete(&url).await?;

        info!("User removed from group");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_user_request_serialization() {
        let request = CreateUserRequest {
            account_enabled: true,
            display_name: "John Doe".to_string(),
            user_principal_name: "john.doe@example.com".to_string(),
            mail_nickname: "john.doe".to_string(),
            password_profile: PasswordProfile {
                password: "P@ssw0rd!".to_string(),
                force_change_password_next_sign_in: true,
            },
            given_name: Some("John".to_string()),
            surname: Some("Doe".to_string()),
            job_title: None,
            department: None,
        };

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["accountEnabled"], true);
        assert_eq!(json["displayName"], "John Doe");
        assert_eq!(json["userPrincipalName"], "john.doe@example.com");
        // Optional None fields should not be present
        assert!(json.get("jobTitle").is_none());
    }

    #[test]
    fn test_update_user_request_partial() {
        let request = UpdateUserRequest {
            display_name: Some("Jane Doe".to_string()),
            ..Default::default()
        };

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["displayName"], "Jane Doe");
        // Other fields should not be present
        assert!(json.get("accountEnabled").is_none());
        assert!(json.get("givenName").is_none());
    }
}
