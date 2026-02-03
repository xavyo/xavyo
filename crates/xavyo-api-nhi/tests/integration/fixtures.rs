//! Test fixtures for xavyo-api-nhi integration tests.
//!
//! Provides fixture data structures and builders for creating test scenarios.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Service account fixture for testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountFixture {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub purpose: String,
    pub owner_id: Uuid,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

impl ServiceAccountFixture {
    /// Create a new service account fixture.
    pub fn new(tenant_id: Uuid, owner_id: Uuid, name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            name: name.to_string(),
            purpose: format!("Test purpose for {}", name),
            owner_id,
            status: "active".to_string(),
            created_at: Utc::now(),
        }
    }

    /// Builder method to set status.
    pub fn with_status(mut self, status: &str) -> Self {
        self.status = status.to_string();
        self
    }
}

/// NHI fixture for unified listing tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiFixture {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub nhi_type: String,
    pub owner_id: Uuid,
    pub status: String,
    pub risk_score: i32,
    pub created_at: DateTime<Utc>,
}

impl NhiFixture {
    /// Create a service account NHI fixture.
    pub fn service_account(tenant_id: Uuid, owner_id: Uuid, name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            name: name.to_string(),
            description: Some(format!("Service account: {}", name)),
            nhi_type: "service_account".to_string(),
            owner_id,
            status: "active".to_string(),
            risk_score: 25,
            created_at: Utc::now(),
        }
    }

    /// Create an AI agent NHI fixture.
    pub fn ai_agent(tenant_id: Uuid, owner_id: Uuid, name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            name: name.to_string(),
            description: Some(format!("AI agent: {}", name)),
            nhi_type: "ai_agent".to_string(),
            owner_id,
            status: "active".to_string(),
            risk_score: 35,
            created_at: Utc::now(),
        }
    }

    /// Builder method to set risk score.
    pub fn with_risk_score(mut self, score: i32) -> Self {
        self.risk_score = score;
        self
    }

    /// Builder method to set status.
    pub fn with_status(mut self, status: &str) -> Self {
        self.status = status.to_string();
        self
    }
}

/// Credential fixture for credential rotation tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialFixture {
    pub id: Uuid,
    pub nhi_id: Uuid,
    pub tenant_id: Uuid,
    pub credential_type: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl CredentialFixture {
    /// Create a new credential fixture.
    pub fn new(nhi_id: Uuid, tenant_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            nhi_id,
            tenant_id,
            credential_type: "api_key".to_string(),
            is_active: true,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    /// Builder method to set credential type.
    pub fn with_type(mut self, credential_type: &str) -> Self {
        self.credential_type = credential_type.to_string();
        self
    }

    /// Builder method to set expiration.
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Builder method to set active status.
    pub fn with_active(mut self, is_active: bool) -> Self {
        self.is_active = is_active;
        self
    }
}

/// Risk score fixture for governance tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreFixture {
    pub nhi_id: Uuid,
    pub score: i32,
    pub level: String,
    pub factors: Vec<RiskFactorFixture>,
}

impl RiskScoreFixture {
    /// Create a low risk score fixture.
    pub fn low(nhi_id: Uuid) -> Self {
        Self {
            nhi_id,
            score: 20,
            level: "low".to_string(),
            factors: vec![RiskFactorFixture::new("credential_age", 10)],
        }
    }

    /// Create a medium risk score fixture.
    pub fn medium(nhi_id: Uuid) -> Self {
        Self {
            nhi_id,
            score: 50,
            level: "medium".to_string(),
            factors: vec![
                RiskFactorFixture::new("credential_age", 20),
                RiskFactorFixture::new("unused_permissions", 15),
                RiskFactorFixture::new("inactivity", 15),
            ],
        }
    }

    /// Create a high risk score fixture.
    pub fn high(nhi_id: Uuid) -> Self {
        Self {
            nhi_id,
            score: 80,
            level: "high".to_string(),
            factors: vec![
                RiskFactorFixture::new("credential_age", 30),
                RiskFactorFixture::new("unused_permissions", 25),
                RiskFactorFixture::new("inactivity", 25),
            ],
        }
    }
}

/// Risk factor fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactorFixture {
    pub name: String,
    pub score: i32,
}

impl RiskFactorFixture {
    /// Create a new risk factor.
    pub fn new(name: &str, score: i32) -> Self {
        Self {
            name: name.to_string(),
            score,
        }
    }
}

/// Certification fixture for governance tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationFixture {
    pub id: Uuid,
    pub nhi_id: Uuid,
    pub tenant_id: Uuid,
    pub certified_by: Uuid,
    pub certified_at: DateTime<Utc>,
    pub next_certification_at: Option<DateTime<Utc>>,
}

impl CertificationFixture {
    /// Create a new certification fixture.
    pub fn new(nhi_id: Uuid, tenant_id: Uuid, certified_by: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            nhi_id,
            tenant_id,
            certified_by,
            certified_at: Utc::now(),
            next_certification_at: None,
        }
    }

    /// Builder method to set next certification date.
    pub fn with_next_certification(mut self, next_at: DateTime<Utc>) -> Self {
        self.next_certification_at = Some(next_at);
        self
    }
}
