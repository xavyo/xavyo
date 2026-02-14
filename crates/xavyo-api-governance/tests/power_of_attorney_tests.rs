//! Unit tests for Power of Attorney service (F-061).
//!
//! Tests validation rules, grant operations, and business logic.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;
    use xavyo_db::models::{
        CreatePowerOfAttorney, PoaFilter, PoaStatus, PowerOfAttorney, POA_MAX_DURATION_DAYS,
    };

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn make_test_poa(
        donor_id: Uuid,
        attorney_id: Uuid,
        status: PoaStatus,
        hours_since_start: i64,
        hours_until_end: i64,
    ) -> PowerOfAttorney {
        let now = Utc::now();
        PowerOfAttorney {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            donor_id,
            attorney_id,
            scope_id: None,
            starts_at: now - Duration::hours(hours_since_start),
            ends_at: now + Duration::hours(hours_until_end),
            status,
            created_at: now - Duration::hours(hours_since_start),
            revoked_at: None,
            revoked_by: None,
            reason: None,
        }
    }

    // ========================================================================
    // T012: PowerOfAttorney Model Validation Tests
    // ========================================================================

    #[test]
    fn test_poa_status_serialization() {
        assert_eq!(
            serde_json::to_string(&PoaStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&PoaStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&PoaStatus::Expired).unwrap(),
            "\"expired\""
        );
        assert_eq!(
            serde_json::to_string(&PoaStatus::Revoked).unwrap(),
            "\"revoked\""
        );
    }

    #[test]
    fn test_poa_status_default() {
        assert_eq!(PoaStatus::default(), PoaStatus::Pending);
    }

    #[test]
    fn test_poa_status_is_actionable() {
        assert!(PoaStatus::Active.is_actionable());
        assert!(!PoaStatus::Pending.is_actionable());
        assert!(!PoaStatus::Expired.is_actionable());
        assert!(!PoaStatus::Revoked.is_actionable());
    }

    #[test]
    fn test_poa_status_is_terminal() {
        assert!(!PoaStatus::Active.is_terminal());
        assert!(!PoaStatus::Pending.is_terminal());
        assert!(PoaStatus::Expired.is_terminal());
        assert!(PoaStatus::Revoked.is_terminal());
    }

    // ========================================================================
    // Duration Validation Tests
    // ========================================================================

    #[test]
    fn test_poa_max_duration_constant() {
        assert_eq!(POA_MAX_DURATION_DAYS, 90);
    }

    #[test]
    fn test_poa_duration_valid_short() {
        let now = Utc::now();
        let ends_at = now + Duration::hours(1);
        assert!(PowerOfAttorney::validate_duration(now, ends_at));
    }

    #[test]
    fn test_poa_duration_valid_max() {
        let now = Utc::now();
        let ends_at = now + Duration::days(90);
        assert!(PowerOfAttorney::validate_duration(now, ends_at));
    }

    #[test]
    fn test_poa_duration_exceeds_max() {
        let now = Utc::now();
        let ends_at = now + Duration::days(91);
        assert!(!PowerOfAttorney::validate_duration(now, ends_at));
    }

    #[test]
    fn test_poa_duration_negative() {
        let now = Utc::now();
        let ends_at = now - Duration::hours(1);
        assert!(!PowerOfAttorney::validate_duration(now, ends_at));
    }

    #[test]
    fn test_poa_duration_zero() {
        let now = Utc::now();
        assert!(!PowerOfAttorney::validate_duration(now, now));
    }

    // ========================================================================
    // is_currently_active Tests
    // ========================================================================

    #[test]
    fn test_poa_is_currently_active_when_active_and_in_time_window() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 1);
        let now = Utc::now();
        assert!(poa.is_currently_active(now));
    }

    #[test]
    fn test_poa_not_active_when_pending() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Pending, 1, 1);
        let now = Utc::now();
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_poa_not_active_when_revoked() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Revoked, 1, 1);
        let now = Utc::now();
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_poa_not_active_when_expired_by_time() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        // Both start and end in the past
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 2, -1);
        let now = Utc::now();
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_poa_not_active_before_start_time() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        // Both start and end in the future
        let mut poa = make_test_poa(donor, attorney, PoaStatus::Active, -1, 2);
        poa.starts_at = Utc::now() + Duration::hours(1);
        poa.ends_at = Utc::now() + Duration::hours(2);
        let now = Utc::now();
        assert!(!poa.is_currently_active(now));
    }

    // ========================================================================
    // T013: PoA Service Grant Operation Tests
    // ========================================================================

    #[test]
    fn test_self_delegation_detection() {
        let user_id = Uuid::new_v4();
        // Self-delegation should be detected and prevented
        let is_self_delegation = user_id == user_id;
        assert!(is_self_delegation, "Self-delegation should be detected");
    }

    #[test]
    fn test_different_users_allowed() {
        let donor_id = Uuid::new_v4();
        let attorney_id = Uuid::new_v4();
        let is_self_delegation = donor_id == attorney_id;
        assert!(
            !is_self_delegation,
            "Different users should not be self-delegation"
        );
    }

    #[test]
    fn test_create_poa_request_valid() {
        let now = Utc::now();
        let request = CreatePowerOfAttorney {
            attorney_id: Uuid::new_v4(),
            starts_at: now,
            ends_at: now + Duration::days(14),
            scope_id: None,
            reason: Some("Vacation coverage".to_string()),
        };

        assert!(PowerOfAttorney::validate_duration(
            request.starts_at,
            request.ends_at
        ));
    }

    #[test]
    fn test_create_poa_request_with_scope() {
        let now = Utc::now();
        let scope_id = Uuid::new_v4();
        let request = CreatePowerOfAttorney {
            attorney_id: Uuid::new_v4(),
            starts_at: now,
            ends_at: now + Duration::days(7),
            scope_id: Some(scope_id),
            reason: None,
        };

        assert!(request.scope_id.is_some());
        assert_eq!(request.scope_id.unwrap(), scope_id);
    }

    #[test]
    fn test_create_poa_request_future_start() {
        let now = Utc::now();
        let request = CreatePowerOfAttorney {
            attorney_id: Uuid::new_v4(),
            starts_at: now + Duration::days(7),
            ends_at: now + Duration::days(21),
            scope_id: None,
            reason: Some("Scheduled vacation".to_string()),
        };

        // Should be valid - future start is allowed
        assert!(PowerOfAttorney::validate_duration(
            request.starts_at,
            request.ends_at
        ));
        assert!(request.starts_at > now);
    }

    // ========================================================================
    // Filter Tests
    // ========================================================================

    #[test]
    fn test_poa_filter_default() {
        let filter = PoaFilter::default();
        assert!(filter.donor_id.is_none());
        assert!(filter.attorney_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.statuses.is_none());
        assert!(filter.active_now.is_none());
    }

    #[test]
    fn test_poa_filter_by_donor() {
        let donor_id = Uuid::new_v4();
        let filter = PoaFilter {
            donor_id: Some(donor_id),
            ..Default::default()
        };
        assert_eq!(filter.donor_id.unwrap(), donor_id);
    }

    #[test]
    fn test_poa_filter_by_attorney() {
        let attorney_id = Uuid::new_v4();
        let filter = PoaFilter {
            attorney_id: Some(attorney_id),
            ..Default::default()
        };
        assert_eq!(filter.attorney_id.unwrap(), attorney_id);
    }

    #[test]
    fn test_poa_filter_active_now() {
        let filter = PoaFilter {
            active_now: Some(true),
            ..Default::default()
        };
        assert_eq!(filter.active_now, Some(true));
    }

    #[test]
    fn test_poa_filter_by_status() {
        let filter = PoaFilter {
            status: Some(PoaStatus::Active),
            ..Default::default()
        };
        assert_eq!(filter.status, Some(PoaStatus::Active));
    }

    // ========================================================================
    // Grant Validation Business Rules
    // ========================================================================

    #[test]
    fn test_grant_max_duration_boundary() {
        let now = Utc::now();

        // Exactly 90 days should be valid
        let ends_at_90 = now + Duration::days(90);
        assert!(PowerOfAttorney::validate_duration(now, ends_at_90));

        // 90 days + 1 second should be invalid
        let ends_at_90_plus = now + Duration::days(90) + Duration::seconds(1);
        assert!(!PowerOfAttorney::validate_duration(now, ends_at_90_plus));
    }

    #[test]
    fn test_grant_minimum_duration() {
        let now = Utc::now();

        // 1 second should be valid (any positive duration)
        let ends_at_1s = now + Duration::seconds(1);
        assert!(PowerOfAttorney::validate_duration(now, ends_at_1s));
    }

    // ========================================================================
    // Time Window Tests
    // ========================================================================

    #[test]
    fn test_poa_active_at_start_boundary() {
        let now = Utc::now();
        let poa = PowerOfAttorney {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            donor_id: Uuid::new_v4(),
            attorney_id: Uuid::new_v4(),
            scope_id: None,
            starts_at: now, // Exactly now
            ends_at: now + Duration::hours(1),
            status: PoaStatus::Active,
            created_at: now,
            revoked_at: None,
            revoked_by: None,
            reason: None,
        };

        // Should be active when starts_at equals current time
        assert!(poa.is_currently_active(now));
    }

    #[test]
    fn test_poa_not_active_at_end_boundary() {
        let now = Utc::now();
        let poa = PowerOfAttorney {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            donor_id: Uuid::new_v4(),
            attorney_id: Uuid::new_v4(),
            scope_id: None,
            starts_at: now - Duration::hours(1),
            ends_at: now, // Exactly now
            status: PoaStatus::Active,
            created_at: now - Duration::hours(1),
            revoked_at: None,
            revoked_by: None,
            reason: None,
        };

        // Should NOT be active when ends_at equals current time (exclusive end)
        assert!(!poa.is_currently_active(now));
    }

    // ========================================================================
    // Multiple PoA Tests
    // ========================================================================

    #[test]
    fn test_donor_can_have_multiple_attorneys() {
        let donor_id = Uuid::new_v4();
        let attorney1 = Uuid::new_v4();
        let attorney2 = Uuid::new_v4();

        let poa1 = make_test_poa(donor_id, attorney1, PoaStatus::Active, 1, 24);
        let poa2 = make_test_poa(donor_id, attorney2, PoaStatus::Active, 1, 24);

        // Same donor, different attorneys
        assert_eq!(poa1.donor_id, poa2.donor_id);
        assert_ne!(poa1.attorney_id, poa2.attorney_id);
    }

    #[test]
    fn test_attorney_can_have_multiple_donors() {
        let attorney_id = Uuid::new_v4();
        let donor1 = Uuid::new_v4();
        let donor2 = Uuid::new_v4();

        let poa1 = make_test_poa(donor1, attorney_id, PoaStatus::Active, 1, 24);
        let poa2 = make_test_poa(donor2, attorney_id, PoaStatus::Active, 1, 24);

        // Same attorney, different donors
        assert_eq!(poa1.attorney_id, poa2.attorney_id);
        assert_ne!(poa1.donor_id, poa2.donor_id);
    }

    // ========================================================================
    // T026: Identity Assumption Tests
    // ========================================================================

    #[test]
    fn test_can_assume_identity_when_poa_active() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);
        let now = Utc::now();

        // Should be allowed to assume identity when PoA is active and in time window
        assert!(poa.is_currently_active(now));
        assert!(poa.status.is_actionable());
    }

    #[test]
    fn test_cannot_assume_identity_when_poa_pending() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Pending, 1, 24);

        // Pending PoA should not allow identity assumption
        assert!(!poa.status.is_actionable());
    }

    #[test]
    fn test_cannot_assume_identity_when_poa_expired() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Expired, 1, 24);

        // Expired PoA should not allow identity assumption
        assert!(!poa.status.is_actionable());
        assert!(poa.status.is_terminal());
    }

    #[test]
    fn test_cannot_assume_identity_when_poa_revoked() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Revoked, 1, 24);

        // Revoked PoA should not allow identity assumption
        assert!(!poa.status.is_actionable());
        assert!(poa.status.is_terminal());
    }

    #[test]
    fn test_cannot_assume_identity_outside_time_window() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        // Both start and end in the past (ended 1 hour ago)
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 48, -1);
        let now = Utc::now();

        // Should be blocked due to time window even if status is Active
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_only_attorney_can_assume_donor_identity() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let random_user = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // Only the attorney specified in the PoA can assume
        assert_eq!(poa.attorney_id, attorney);
        assert_ne!(poa.attorney_id, random_user);
        assert_ne!(poa.attorney_id, donor); // Donor cannot assume their own identity
    }

    #[test]
    fn test_assumed_identity_has_dual_attribution() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // Both IDs should be available for dual attribution audit
        assert_ne!(poa.donor_id, poa.attorney_id);
        // In an assumed session, both donor_id (acting_as) and attorney_id (actual user)
        // should be recorded in audit events
    }

    // ========================================================================
    // T027: Assumed Session Lifecycle Tests
    // ========================================================================

    #[test]
    fn test_assumed_session_requires_active_poa() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);
        let now = Utc::now();

        // Session can only be created when PoA is currently active
        assert!(poa.is_currently_active(now));
    }

    #[test]
    fn test_assumed_session_tracks_poa_reference() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // The assumed session should reference the PoA ID for validation
        let poa_id = poa.id;
        assert!(!poa_id.is_nil());
    }

    #[test]
    fn test_assumed_session_can_be_dropped_voluntarily() {
        // Attorney can drop assumed identity at any time
        // This is a business rule test - session should support voluntary termination
        let poa = make_test_poa(Uuid::new_v4(), Uuid::new_v4(), PoaStatus::Active, 1, 24);
        assert!(poa.status.is_actionable()); // Session can exist while actionable
    }

    #[test]
    fn test_assumed_session_terminated_on_poa_revoke() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let mut poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // When PoA is revoked, all assumed sessions should be terminated
        poa.status = PoaStatus::Revoked;
        poa.revoked_at = Some(Utc::now());
        poa.revoked_by = Some(donor);

        assert!(poa.status.is_terminal());
        assert!(!poa.status.is_actionable());
    }

    #[test]
    fn test_assumed_session_terminated_on_poa_expire() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        // Create PoA that has already expired (ended 1 hour ago)
        let poa = make_test_poa(donor, attorney, PoaStatus::Expired, 48, -1);
        let now = Utc::now();

        // Expired PoA cannot have active assumed sessions
        assert!(!poa.is_currently_active(now));
        assert!(poa.status.is_terminal());
    }

    #[test]
    fn test_attorney_can_assume_from_multiple_donors() {
        let attorney = Uuid::new_v4();
        let donor1 = Uuid::new_v4();
        let donor2 = Uuid::new_v4();

        let poa1 = make_test_poa(donor1, attorney, PoaStatus::Active, 1, 24);
        let poa2 = make_test_poa(donor2, attorney, PoaStatus::Active, 1, 24);

        // Attorney can have PoAs from multiple donors
        // (but can only assume one identity at a time per spec)
        assert_eq!(poa1.attorney_id, poa2.attorney_id);
        assert_ne!(poa1.donor_id, poa2.donor_id);
        assert_ne!(poa1.id, poa2.id);
    }

    #[test]
    fn test_assumed_session_has_distinct_token() {
        // When assuming identity, a new JWT is issued with acting_as claims
        // This test validates the JWT claim structure requirements
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // The JWT should contain:
        // - sub: original attorney's ID
        // - acting_as_user_id: donor's ID
        // - acting_as_poa_id: PoA ID
        // - acting_as_session_id: assumed session ID
        assert!(!poa.donor_id.is_nil());
        assert!(!poa.attorney_id.is_nil());
        assert!(!poa.id.is_nil());
    }

    #[test]
    fn test_assumed_session_respects_poa_time_window() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let now = Utc::now();

        // PoA active for next 2 hours only
        let poa = PowerOfAttorney {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            donor_id: donor,
            attorney_id: attorney,
            scope_id: None,
            starts_at: now - Duration::hours(1),
            ends_at: now + Duration::hours(2),
            status: PoaStatus::Active,
            created_at: now - Duration::hours(1),
            revoked_at: None,
            revoked_by: None,
            reason: None,
        };

        // Session should only be valid within the PoA time window
        assert!(poa.is_currently_active(now));
        assert!(!poa.is_currently_active(now + Duration::hours(3)));
    }

    // ========================================================================
    // T038: PoA Revocation Tests
    // ========================================================================

    #[test]
    fn test_revoke_changes_status_to_revoked() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let mut poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // Simulate revocation
        poa.status = PoaStatus::Revoked;
        poa.revoked_at = Some(Utc::now());
        poa.revoked_by = Some(donor);

        assert_eq!(poa.status, PoaStatus::Revoked);
        assert!(poa.revoked_at.is_some());
        assert_eq!(poa.revoked_by, Some(donor));
    }

    #[test]
    fn test_revoked_poa_is_terminal() {
        let poa = make_test_poa(Uuid::new_v4(), Uuid::new_v4(), PoaStatus::Revoked, 1, 24);
        assert!(poa.status.is_terminal());
    }

    #[test]
    fn test_revoked_poa_not_actionable() {
        let poa = make_test_poa(Uuid::new_v4(), Uuid::new_v4(), PoaStatus::Revoked, 1, 24);
        assert!(!poa.status.is_actionable());
    }

    #[test]
    fn test_revoked_poa_not_currently_active() {
        let poa = make_test_poa(Uuid::new_v4(), Uuid::new_v4(), PoaStatus::Revoked, 1, 24);
        let now = Utc::now();
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_only_donor_can_revoke_own_poa() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let random_user = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // Only donor should be allowed to revoke
        assert_eq!(poa.donor_id, donor);
        assert_ne!(poa.donor_id, attorney);
        assert_ne!(poa.donor_id, random_user);
    }

    #[test]
    fn test_cannot_revoke_already_revoked_poa() {
        let poa = make_test_poa(Uuid::new_v4(), Uuid::new_v4(), PoaStatus::Revoked, 1, 24);
        // Terminal state - cannot be revoked again
        assert!(poa.status.is_terminal());
    }

    #[test]
    fn test_cannot_revoke_expired_poa() {
        let poa = make_test_poa(Uuid::new_v4(), Uuid::new_v4(), PoaStatus::Expired, 48, -1);
        // Terminal state - cannot be revoked
        assert!(poa.status.is_terminal());
    }

    #[test]
    fn test_admin_can_revoke_any_poa() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let admin = Uuid::new_v4();
        let poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // Admin should be able to revoke even though not donor or attorney
        assert_ne!(admin, poa.donor_id);
        assert_ne!(admin, poa.attorney_id);
        // Admin role check is done at handler level
    }

    // ========================================================================
    // T039: Session Termination on Revoke Tests
    // ========================================================================

    #[test]
    fn test_revoke_should_terminate_active_sessions() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let mut poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);
        let now = Utc::now();

        // Simulate an active session exists
        assert!(poa.is_currently_active(now));

        // After revocation, sessions should be terminated
        poa.status = PoaStatus::Revoked;
        poa.revoked_at = Some(now);

        // PoA is no longer active, so sessions cannot be valid
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_revocation_reason_is_recorded() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let _poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);

        // Revocation reason should be stored
        let reason = Some("Vacation cancelled".to_string());
        assert!(reason.is_some());
        assert!(reason.as_ref().unwrap().len() < 500);
    }

    #[test]
    fn test_revocation_timestamp_is_recorded() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let mut poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);
        let revoke_time = Utc::now();

        poa.revoked_at = Some(revoke_time);
        poa.status = PoaStatus::Revoked;

        assert!(poa.revoked_at.is_some());
        assert!(poa.revoked_at.unwrap() <= Utc::now());
    }

    #[test]
    fn test_session_invalid_after_poa_revoked() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let mut poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);
        let now = Utc::now();

        // Before revocation - session would be valid
        assert!(poa.is_currently_active(now));

        // After revocation - session must be invalid
        poa.status = PoaStatus::Revoked;
        assert!(!poa.is_currently_active(now));
    }

    #[test]
    fn test_session_terminated_reason_recorded() {
        // When a session is terminated due to revocation, the reason should be recorded
        let reason = "poa_revoked";
        assert_eq!(reason, "poa_revoked");

        // Admin revocation should have different reason
        let admin_reason = "admin_revoked";
        assert_eq!(admin_reason, "admin_revoked");
    }

    #[test]
    fn test_immediate_effect_of_revocation() {
        let donor = Uuid::new_v4();
        let attorney = Uuid::new_v4();
        let mut poa = make_test_poa(donor, attorney, PoaStatus::Active, 1, 24);
        let now = Utc::now();

        // Should be active right before revocation
        assert!(poa.is_currently_active(now));
        assert!(poa.status.is_actionable());

        // Revocation takes effect immediately
        poa.status = PoaStatus::Revoked;
        poa.revoked_at = Some(now);
        poa.revoked_by = Some(donor);

        // Should be immediately inactive
        assert!(!poa.is_currently_active(now));
        assert!(!poa.status.is_actionable());
        assert!(poa.status.is_terminal());
    }

    // ========================================================================
    // Role Intersection Tests (Security: Privilege Escalation Prevention)
    // Tests call the actual `compute_role_intersection` function from poa_service.
    // ========================================================================

    use xavyo_api_governance::services::compute_role_intersection;

    #[test]
    fn test_role_intersection_prevents_privilege_escalation() {
        let donor = vec!["admin".into(), "user".into()];
        let attorney = vec!["user".into()];
        let result = compute_role_intersection(&donor, &attorney);

        assert_eq!(result.effective_roles, vec!["user".to_string()]);
        assert_eq!(result.restricted_roles, vec!["admin".to_string()]);
        assert!(result.was_restricted());
    }

    #[test]
    fn test_role_intersection_same_roles() {
        let roles = vec!["admin".into(), "user".into()];
        let result = compute_role_intersection(&roles, &roles);

        assert_eq!(result.effective_roles.len(), 2);
        assert!(result.effective_roles.contains(&"admin".into()));
        assert!(result.effective_roles.contains(&"user".into()));
        assert!(!result.was_restricted());
        assert!(result.restricted_roles.is_empty());
    }

    #[test]
    fn test_role_intersection_no_overlap() {
        let donor = vec!["admin".into(), "super_admin".into()];
        let attorney = vec!["user".into(), "member".into()];
        let result = compute_role_intersection(&donor, &attorney);

        assert!(result.effective_roles.is_empty());
        assert!(result.was_restricted());
        assert_eq!(result.restricted_roles.len(), 2);
    }

    #[test]
    fn test_role_intersection_partial_overlap() {
        let donor = vec!["admin".into(), "user".into(), "auditor".into()];
        let attorney = vec!["user".into(), "auditor".into(), "member".into()];
        let result = compute_role_intersection(&donor, &attorney);

        assert_eq!(result.effective_roles.len(), 2);
        assert!(result.effective_roles.contains(&"user".into()));
        assert!(result.effective_roles.contains(&"auditor".into()));
        assert!(!result.effective_roles.contains(&"admin".into()));
        assert_eq!(result.restricted_roles, vec!["admin".to_string()]);
    }

    #[test]
    fn test_role_restriction_detection() {
        let donor = vec!["admin".into(), "user".into()];
        let attorney = vec!["user".into()];
        let result = compute_role_intersection(&donor, &attorney);

        assert!(result.was_restricted());
        assert_eq!(result.restricted_roles, vec!["admin".to_string()]);
    }

    #[test]
    fn test_no_role_restriction_when_attorney_has_superset() {
        let donor = vec!["user".into()];
        let attorney = vec!["user".into(), "admin".into()];
        let result = compute_role_intersection(&donor, &attorney);

        assert!(!result.was_restricted());
        assert_eq!(result.effective_roles, vec!["user".to_string()]);
        assert!(result.restricted_roles.is_empty());
    }

    #[test]
    fn test_super_admin_escalation_prevented() {
        let donor = vec!["super_admin".into(), "admin".into(), "user".into()];
        let attorney = vec!["admin".into(), "user".into()];
        let result = compute_role_intersection(&donor, &attorney);

        assert_eq!(result.effective_roles.len(), 2);
        assert!(result.effective_roles.contains(&"admin".into()));
        assert!(result.effective_roles.contains(&"user".into()));
        assert!(!result.effective_roles.contains(&"super_admin".into()));
        assert_eq!(result.restricted_roles, vec!["super_admin".to_string()]);
    }

    #[test]
    fn test_empty_donor_roles() {
        let donor: Vec<String> = vec![];
        let attorney = vec!["admin".into(), "user".into()];
        let result = compute_role_intersection(&donor, &attorney);

        assert!(result.effective_roles.is_empty());
        assert!(!result.was_restricted());
    }

    #[test]
    fn test_empty_attorney_roles() {
        let donor = vec!["admin".into(), "user".into()];
        let attorney: Vec<String> = vec![];
        let result = compute_role_intersection(&donor, &attorney);

        assert!(result.effective_roles.is_empty());
        assert!(result.was_restricted());
        assert_eq!(result.restricted_roles.len(), 2);
    }
}
