//! Security policy data models for the CLI

use serde::{Deserialize, Serialize};

/// Generic policy response from the API (policies are JSON objects)
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    #[serde(flatten)]
    pub data: serde_json::Value,
}
