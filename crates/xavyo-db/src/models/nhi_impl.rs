//! NonHumanIdentity trait implementations for database models.
//!
//! This module implements the unified NHI trait (F108) for service accounts
//! and AI agents, enabling unified governance operations across all non-human
//! identity types.

use chrono::{DateTime, Utc};
use uuid::Uuid;
use xavyo_nhi::{NhiStatus, NhiType, NonHumanIdentity};

#[cfg(test)]
use xavyo_nhi::NhiRiskLevel;

use super::ai_agent::AiAgent;
use super::gov_service_account::{GovServiceAccount, ServiceAccountStatus};

// ============================================================================
// GovServiceAccount Implementation
// ============================================================================

impl NonHumanIdentity for GovServiceAccount {
    fn id(&self) -> Uuid {
        self.id
    }

    fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        Some(&self.purpose)
    }

    fn nhi_type(&self) -> NhiType {
        NhiType::ServiceAccount
    }

    fn owner_id(&self) -> Uuid {
        self.owner_id
    }

    fn backup_owner_id(&self) -> Option<Uuid> {
        self.backup_owner_id
    }

    fn status(&self) -> NhiStatus {
        match self.status {
            ServiceAccountStatus::Active => NhiStatus::Active,
            ServiceAccountStatus::Expired => NhiStatus::Expired,
            ServiceAccountStatus::Suspended => NhiStatus::Suspended,
        }
    }

    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    fn last_activity_at(&self) -> Option<DateTime<Utc>> {
        self.last_used_at
    }

    fn risk_score(&self) -> u32 {
        // Calculate risk score based on staleness, credential age, and certification status
        let mut score: u32 = 0;

        // Staleness factor (40 points max)
        if let Some(last_used) = self.last_used_at {
            let days_since_use = (Utc::now() - last_used).num_days();
            score += match days_since_use {
                d if d >= 90 => 40,
                d if d >= 30 => 20,
                _ => 0,
            };
        } else {
            // Never used = high staleness risk
            score += 40;
        }

        // Credential age factor (30 points max)
        if let Some(last_rotation) = self.last_rotation_at {
            let days_since_rotation = (Utc::now() - last_rotation).num_days();
            let interval = self.rotation_interval_days.unwrap_or(90) as i64;
            score += match days_since_rotation {
                d if d >= interval * 2 => 30,
                d if d >= interval => 15,
                _ => 0,
            };
        } else {
            // Never rotated = moderate risk
            score += 15;
        }

        // Certification factor (30 points max)
        if let Some(last_cert) = self.last_certified_at {
            let days_since_cert = (Utc::now() - last_cert).num_days();
            score += match days_since_cert {
                d if d >= 365 => 30,
                d if d >= 180 => 15,
                _ => 0,
            };
        } else {
            // Never certified = high certification risk
            score += 30;
        }

        // Cap at 100
        score.min(100)
    }

    fn next_certification_at(&self) -> Option<DateTime<Utc>> {
        // Service accounts require certification every 365 days
        self.last_certified_at
            .map(|cert| cert + chrono::Duration::days(365))
    }

    fn last_certified_at(&self) -> Option<DateTime<Utc>> {
        self.last_certified_at
    }
}

// ============================================================================
// AiAgent Implementation
// ============================================================================

impl NonHumanIdentity for AiAgent {
    fn id(&self) -> Uuid {
        self.id
    }

    fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn nhi_type(&self) -> NhiType {
        NhiType::AiAgent
    }

    fn owner_id(&self) -> Uuid {
        // AiAgent has owner_id as Option<Uuid>, but NonHumanIdentity requires Uuid
        // Fall back to a nil UUID if no owner is assigned (should be rare in practice)
        self.owner_id.unwrap_or(Uuid::nil())
    }

    fn backup_owner_id(&self) -> Option<Uuid> {
        // Note: backup_owner_id will be added by migration 1080_001
        // For now, return None until the model is updated
        None
    }

    fn status(&self) -> NhiStatus {
        match self.status.as_str() {
            "active" => NhiStatus::Active,
            "suspended" => NhiStatus::Suspended,
            "expired" => NhiStatus::Expired,
            "pending_certification" => NhiStatus::PendingCertification,
            _ => NhiStatus::Inactive,
        }
    }

    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    fn last_activity_at(&self) -> Option<DateTime<Utc>> {
        self.last_activity_at
    }

    fn risk_score(&self) -> u32 {
        // Map risk_level string to a numeric score (0-100)
        // This provides a default implementation based on the risk_level enum
        match self.risk_level.as_str() {
            "critical" => 90,
            "high" => 70,
            "medium" => 40,
            "low" => 20,
            _ => 0,
        }
    }

    fn next_certification_at(&self) -> Option<DateTime<Utc>> {
        // Note: next_certification_at will be added by migration 1080_001
        // For now, return None until the model is updated
        None
    }

    fn last_certified_at(&self) -> Option<DateTime<Utc>> {
        // Note: last_certified_at will be added by migration 1080_001
        // For now, return None until the model is updated
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --------------------------------------------------------------------------
    // GovServiceAccount Tests
    // --------------------------------------------------------------------------

    fn create_test_service_account() -> GovServiceAccount {
        GovServiceAccount {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "test-service-account".to_string(),
            purpose: "Test service account for unit tests".to_string(),
            owner_id: Uuid::new_v4(),
            status: ServiceAccountStatus::Active,
            expires_at: None,
            last_certified_at: Some(Utc::now() - chrono::Duration::days(30)),
            certified_by: Some(Uuid::new_v4()),
            created_at: Utc::now() - chrono::Duration::days(90),
            updated_at: Utc::now(),
            backup_owner_id: Some(Uuid::new_v4()),
            rotation_interval_days: Some(90),
            last_rotation_at: Some(Utc::now() - chrono::Duration::days(30)),
            last_used_at: Some(Utc::now() - chrono::Duration::days(5)),
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            suspension_reason: None,
            // F108: Anomaly detection fields
            anomaly_threshold: None,
            last_anomaly_check_at: None,
            anomaly_baseline: None,
        }
    }

    #[test]
    fn test_sa_nhi_type() {
        let sa = create_test_service_account();
        assert_eq!(sa.nhi_type(), NhiType::ServiceAccount);
    }

    #[test]
    fn test_sa_nhi_status_active() {
        let sa = create_test_service_account();
        assert_eq!(sa.status(), NhiStatus::Active);
        assert!(sa.is_active());
    }

    #[test]
    fn test_sa_nhi_status_suspended() {
        let mut sa = create_test_service_account();
        sa.status = ServiceAccountStatus::Suspended;
        assert_eq!(sa.status(), NhiStatus::Suspended);
        assert!(!sa.is_active());
    }

    #[test]
    fn test_sa_nhi_status_expired() {
        let mut sa = create_test_service_account();
        sa.status = ServiceAccountStatus::Expired;
        assert_eq!(sa.status(), NhiStatus::Expired);
        assert!(!sa.is_active());
    }

    #[test]
    fn test_sa_description_returns_purpose() {
        let sa = create_test_service_account();
        assert_eq!(
            sa.description(),
            Some("Test service account for unit tests")
        );
    }

    #[test]
    fn test_sa_last_activity_returns_last_used() {
        let sa = create_test_service_account();
        assert!(sa.last_activity_at().is_some());
    }

    #[test]
    fn test_sa_risk_score_low_for_active_account() {
        let sa = create_test_service_account();
        let score = sa.risk_score();
        // Recently used, recently rotated, recently certified = low risk
        assert!(score < 50, "Expected low risk score, got {}", score);
    }

    #[test]
    fn test_sa_risk_score_high_for_stale_account() {
        let mut sa = create_test_service_account();
        sa.last_used_at = Some(Utc::now() - chrono::Duration::days(100)); // Very stale
        sa.last_rotation_at = Some(Utc::now() - chrono::Duration::days(200)); // Never rotated
        sa.last_certified_at = None; // Never certified

        let score = sa.risk_score();
        assert!(score >= 70, "Expected high risk score, got {}", score);
    }

    #[test]
    fn test_sa_risk_level_low() {
        let sa = create_test_service_account();
        let level = sa.risk_level();
        assert_eq!(level, NhiRiskLevel::Low);
    }

    #[test]
    fn test_sa_is_stale() {
        let mut sa = create_test_service_account();
        sa.last_used_at = Some(Utc::now() - chrono::Duration::days(10));

        assert!(!sa.is_stale(30)); // Not stale within 30 days
        assert!(sa.is_stale(5)); // Stale within 5 days
    }

    #[test]
    fn test_sa_is_stale_no_activity() {
        let mut sa = create_test_service_account();
        sa.last_used_at = None;

        // No activity = always stale
        assert!(sa.is_stale(30));
        assert!(sa.is_stale(90));
    }

    #[test]
    fn test_sa_is_expired() {
        let mut sa = create_test_service_account();
        sa.expires_at = Some(Utc::now() - chrono::Duration::days(1));

        assert!(sa.is_expired());
    }

    #[test]
    fn test_sa_not_expired() {
        let mut sa = create_test_service_account();
        sa.expires_at = Some(Utc::now() + chrono::Duration::days(30));

        assert!(!sa.is_expired());
    }

    #[test]
    fn test_sa_needs_certification() {
        let mut sa = create_test_service_account();
        sa.last_certified_at = Some(Utc::now() - chrono::Duration::days(400)); // Over 365 days ago

        assert!(sa.needs_certification());
    }

    #[test]
    fn test_sa_not_needs_certification() {
        let mut sa = create_test_service_account();
        sa.last_certified_at = Some(Utc::now() - chrono::Duration::days(30)); // Recently certified

        assert!(!sa.needs_certification());
    }

    #[test]
    fn test_sa_next_certification_at() {
        let cert_time = Utc::now() - chrono::Duration::days(30);
        let mut sa = create_test_service_account();
        sa.last_certified_at = Some(cert_time);

        let next_cert = sa.next_certification_at();
        assert!(next_cert.is_some());

        let expected = cert_time + chrono::Duration::days(365);
        let diff = (next_cert.unwrap() - expected).num_seconds().abs();
        assert!(diff < 2, "Next certification should be 365 days after last");
    }

    #[test]
    fn test_sa_backup_owner() {
        let sa = create_test_service_account();
        assert!(sa.backup_owner_id().is_some());
    }

    #[test]
    fn test_sa_trait_object_compatible() {
        let sa = create_test_service_account();
        let nhi: &dyn NonHumanIdentity = &sa;

        assert_eq!(nhi.nhi_type(), NhiType::ServiceAccount);
        assert!(nhi.is_active());
    }

    // --------------------------------------------------------------------------
    // AiAgent Tests
    // --------------------------------------------------------------------------

    fn create_test_agent() -> AiAgent {
        AiAgent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-agent".to_string(),
            description: Some("Test AI agent for unit tests".to_string()),
            agent_type: "copilot".to_string(),
            owner_id: Some(Uuid::new_v4()),
            team_id: None,
            backup_owner_id: None,
            model_provider: Some("anthropic".to_string()),
            model_name: Some("claude-sonnet-4".to_string()),
            model_version: Some("20250101".to_string()),
            agent_card_url: Some("https://example.com/.well-known/agent.json".to_string()),
            agent_card_signature: None,
            status: "active".to_string(),
            risk_level: "medium".to_string(),
            max_token_lifetime_secs: 900,
            requires_human_approval: false,
            created_at: Utc::now() - chrono::Duration::days(30),
            updated_at: Utc::now(),
            last_activity_at: Some(Utc::now() - chrono::Duration::days(2)),
            expires_at: Some(Utc::now() + chrono::Duration::days(365)),
            // F108 governance fields
            inactivity_threshold_days: Some(90),
            grace_period_ends_at: None,
            suspension_reason: None,
            rotation_interval_days: None,
            last_rotation_at: None,
            risk_score: None,
            next_certification_at: None,
            last_certified_at: None,
            last_certified_by: None,
        }
    }

    #[test]
    fn test_agent_nhi_type() {
        let agent = create_test_agent();
        assert_eq!(agent.nhi_type(), NhiType::AiAgent);
    }

    #[test]
    fn test_agent_nhi_status_active() {
        let agent = create_test_agent();
        assert_eq!(agent.status(), NhiStatus::Active);
        assert!(agent.is_active());
    }

    #[test]
    fn test_agent_nhi_status_suspended() {
        let mut agent = create_test_agent();
        agent.status = "suspended".to_string();
        assert_eq!(agent.status(), NhiStatus::Suspended);
        assert!(!agent.is_active());
    }

    #[test]
    fn test_agent_nhi_status_expired() {
        let mut agent = create_test_agent();
        agent.status = "expired".to_string();
        assert_eq!(agent.status(), NhiStatus::Expired);
        assert!(!agent.is_active());
    }

    #[test]
    fn test_agent_description() {
        let agent = create_test_agent();
        assert_eq!(agent.description(), Some("Test AI agent for unit tests"));
    }

    #[test]
    fn test_agent_description_none() {
        let mut agent = create_test_agent();
        agent.description = None;
        assert_eq!(agent.description(), None);
    }

    #[test]
    fn test_agent_last_activity() {
        let agent = create_test_agent();
        assert!(agent.last_activity_at().is_some());
    }

    #[test]
    fn test_agent_risk_score_medium() {
        let agent = create_test_agent();
        let score = agent.risk_score();
        assert_eq!(score, 40); // medium = 40
    }

    #[test]
    fn test_agent_risk_score_critical() {
        let mut agent = create_test_agent();
        agent.risk_level = "critical".to_string();
        assert_eq!(agent.risk_score(), 90);
    }

    #[test]
    fn test_agent_risk_score_high() {
        let mut agent = create_test_agent();
        agent.risk_level = "high".to_string();
        assert_eq!(agent.risk_score(), 70);
    }

    #[test]
    fn test_agent_risk_score_low() {
        let mut agent = create_test_agent();
        agent.risk_level = "low".to_string();
        assert_eq!(agent.risk_score(), 20);
    }

    #[test]
    fn test_agent_risk_level_from_score() {
        let agent = create_test_agent();
        let level = agent.risk_level();
        assert_eq!(level, NhiRiskLevel::Medium);
    }

    #[test]
    fn test_agent_is_stale() {
        let mut agent = create_test_agent();
        agent.last_activity_at = Some(Utc::now() - chrono::Duration::days(10));

        assert!(!agent.is_stale(30)); // Not stale within 30 days
        assert!(agent.is_stale(5)); // Stale within 5 days
    }

    #[test]
    fn test_agent_is_stale_no_activity() {
        let mut agent = create_test_agent();
        agent.last_activity_at = None;

        // No activity = always stale
        assert!(agent.is_stale(30));
        assert!(agent.is_stale(90));
    }

    #[test]
    fn test_agent_is_expired() {
        let mut agent = create_test_agent();
        agent.expires_at = Some(Utc::now() - chrono::Duration::days(1));

        assert!(agent.is_expired());
    }

    #[test]
    fn test_agent_not_expired() {
        let agent = create_test_agent();
        assert!(!agent.is_expired());
    }

    #[test]
    fn test_agent_owner_id() {
        let agent = create_test_agent();
        assert_ne!(agent.owner_id(), Uuid::nil());
    }

    #[test]
    fn test_agent_owner_id_none() {
        let mut agent = create_test_agent();
        agent.owner_id = None;
        // Returns nil UUID when no owner is set
        assert_eq!(agent.owner_id(), Uuid::nil());
    }

    #[test]
    fn test_agent_trait_object_compatible() {
        let agent = create_test_agent();
        let nhi: &dyn NonHumanIdentity = &agent;

        assert_eq!(nhi.nhi_type(), NhiType::AiAgent);
        assert!(nhi.is_active());
        assert_eq!(nhi.name(), "test-agent");
    }

    #[test]
    fn test_agent_backup_owner_not_yet_implemented() {
        let agent = create_test_agent();
        // Until migration 1080_001 adds backup_owner_id column
        assert!(agent.backup_owner_id().is_none());
    }

    #[test]
    fn test_agent_certification_not_yet_implemented() {
        let agent = create_test_agent();
        // Until migration 1080_001 adds certification fields
        assert!(agent.next_certification_at().is_none());
        assert!(agent.last_certified_at().is_none());
    }
}
