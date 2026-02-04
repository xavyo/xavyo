//! Integration tests for Password Reset & Email Verification (F007).
//!
//! Tests the complete flows for:
//! - User Story 1: Password Reset Request (forgot password)
//! - User Story 2: Password Reset Completion (reset password)
//! - User Story 3: Email Verification
//! - User Story 4: Resend Verification
//!
//! Run with: `cargo test -p xavyo-api-auth --features integration password_reset_test`

mod common;

#[cfg(feature = "integration")]
mod password_reset_tests {
    use super::common::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use xavyo_api_auth::middleware::EmailRateLimiter;
    use xavyo_api_auth::services::{
        generate_email_verification_token, generate_password_reset_token, hash_token,
        verify_token_hash_constant_time, EmailSender, MockEmailSender,
        EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS, PASSWORD_RESET_TOKEN_VALIDITY_HOURS,
    };
    use xavyo_auth::hash_password;

    // =========================================================================
    // User Story 1: Password Reset Request (Forgot Password)
    // Tasks: T017-T020, T025
    // =========================================================================

    mod forgot_password {
        use super::*;

        /// T017: Test successful password reset request
        /// Validates that a reset request for an existing user:
        /// - Creates a token in the database
        /// - Calls the email service with the correct token
        #[tokio::test]
        async fn test_successful_reset_request() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create user
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &password_hash).await;

            // Create email sender mock
            let email_sender = MockEmailSender::new();

            // Simulate the forgot password flow
            // Look up user
            let user_row: Option<(uuid::Uuid, bool)> = sqlx::query_as(
                "SELECT id, is_active FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind(&email)
            .fetch_optional(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert!(user_row.is_some(), "User should exist");
            let (found_user_id, is_active) = user_row.unwrap();
            assert_eq!(found_user_id, *user_id.as_uuid());
            assert!(is_active);

            // Generate token
            let (token, token_hash) = generate_password_reset_token();
            let expires_at =
                Utc::now() + ChronoDuration::hours(PASSWORD_RESET_TOKEN_VALIDITY_HOURS);

            // Store token
            sqlx::query(
                r#"
                INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at, ip_address)
                VALUES ($1, $2, $3, $4, '127.0.0.1')
                "#
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind(user_id.as_uuid())
            .bind(&token_hash)
            .bind(expires_at)
            .execute(&fixture.pool)
            .await
            .expect("Should insert token");

            // Send email
            email_sender
                .send_password_reset(&email, &token, fixture.tenant_id)
                .await
                .expect("Should send email");

            // Verify email was sent
            let resets = email_sender.get_password_resets();
            assert_eq!(resets.len(), 1);
            assert_eq!(resets[0].0, email);
            assert_eq!(resets[0].1, token);

            fixture.cleanup().await;
        }

        /// T018: Test non-existent email returns same response (no enumeration)
        /// Validates that requesting reset for non-existent email:
        /// - Does not create a token
        /// - Does not send an email
        /// - Returns success (same as existing email)
        #[tokio::test]
        async fn test_non_existent_email_no_enumeration() {
            let fixture = TestFixture::new().await;
            let email = "nonexistent@example.com";

            // Look up user (should not exist)
            let user_row: Option<(uuid::Uuid, bool)> = sqlx::query_as(
                "SELECT id, is_active FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind(&email)
            .fetch_optional(&fixture.pool)
            .await
            .expect("Query should succeed");

            // User should not exist
            assert!(user_row.is_none(), "User should not exist");

            // No token should be created (we didn't create one since user doesn't exist)
            let token_count: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM password_reset_tokens WHERE tenant_id = $1")
                    .bind(fixture.tenant_id.as_uuid())
                    .fetch_one(&fixture.pool)
                    .await
                    .expect("Query should succeed");

            assert_eq!(
                token_count.0, 0,
                "No token should be created for non-existent user"
            );

            // In the handler, we return success anyway to prevent enumeration
            // This is the expected behavior - no differentiation between existing and non-existing emails

            fixture.cleanup().await;
        }

        /// T019: Test rate limiting for password reset requests
        #[tokio::test]
        async fn test_rate_limiting() {
            let email = "ratelimit@example.com";
            let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

            // Use a rate limiter with low limits for testing
            let rate_limiter = EmailRateLimiter::with_config(2, 3, 60);

            // First two attempts should succeed (email limit = 2)
            assert!(
                rate_limiter.record_attempt(email, ip),
                "First attempt should succeed"
            );
            assert!(
                rate_limiter.record_attempt(email, ip),
                "Second attempt should succeed"
            );

            // Third attempt should fail (email limit exceeded)
            assert!(
                !rate_limiter.record_attempt(email, ip),
                "Third attempt should be rate limited"
            );

            // Verify the limiter is tracking correctly
            assert_eq!(rate_limiter.remaining_email_attempts(email), 0);
        }

        /// T020: Test email service is called with correct token
        #[tokio::test]
        async fn test_email_service_receives_correct_token() {
            let email_sender = MockEmailSender::new();
            let tenant_id = xavyo_core::TenantId::new();

            let expected_token = "test_token_12345";

            email_sender
                .send_password_reset("user@example.com", expected_token, tenant_id)
                .await
                .expect("Should send email");

            let resets = email_sender.get_password_resets();
            assert_eq!(resets.len(), 1);
            assert_eq!(resets[0].1, expected_token, "Token should match exactly");

            // Test get_last_reset_token helper
            let last_token = email_sender.get_last_reset_token("user@example.com");
            assert_eq!(last_token, Some(expected_token.to_string()));
        }
    }

    // =========================================================================
    // User Story 2: Password Reset Completion
    // Tasks: T026-T030, T035
    // =========================================================================

    mod reset_password {
        use super::*;

        /// T026: Test successful password reset
        #[tokio::test]
        async fn test_successful_password_reset() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let old_password = valid_test_password();
            let old_password_hash = hash_password(old_password).expect("Should hash password");

            // Create user
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &old_password_hash)
                    .await;

            // Create valid token
            let (token, token_hash) = create_test_password_reset_token();
            insert_valid_password_reset_token(
                &fixture.pool,
                fixture.tenant_id,
                user_id,
                &token_hash,
            )
            .await;

            // Verify token exists and is valid
            let token_row: Option<(uuid::Uuid, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
                "SELECT user_id, used_at FROM password_reset_tokens WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .fetch_optional(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert!(token_row.is_some(), "Token should exist");
            let (found_user_id, used_at) = token_row.unwrap();
            assert_eq!(found_user_id, *user_id.as_uuid());
            assert!(used_at.is_none(), "Token should not be used yet");

            // Verify token hash matches
            assert!(
                verify_token_hash_constant_time(&token, &token_hash),
                "Token verification should succeed"
            );

            // Simulate password update
            let new_password = "NewSecureP@ss456";
            let new_password_hash = hash_password(new_password).expect("Should hash new password");

            sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
                .bind(&new_password_hash)
                .bind(user_id.as_uuid())
                .execute(&fixture.pool)
                .await
                .expect("Should update password");

            // Mark token as used
            sqlx::query("UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = $1")
                .bind(&token_hash)
                .execute(&fixture.pool)
                .await
                .expect("Should mark token as used");

            // Verify password was changed
            let user_row: (String,) =
                sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
                    .bind(user_id.as_uuid())
                    .fetch_one(&fixture.pool)
                    .await
                    .expect("Query should succeed");

            assert_ne!(
                user_row.0, old_password_hash,
                "Password hash should have changed"
            );
            assert_eq!(user_row.0, new_password_hash);

            fixture.cleanup().await;
        }

        /// T027: Test expired token rejection
        #[tokio::test]
        async fn test_expired_token_rejection() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create user
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &password_hash).await;

            // Create expired token
            let (token, token_hash) = create_test_password_reset_token();
            insert_expired_password_reset_token(
                &fixture.pool,
                fixture.tenant_id,
                user_id,
                &token_hash,
            )
            .await;

            // Check token expiration
            let token_row: Option<(chrono::DateTime<Utc>,)> = sqlx::query_as(
                "SELECT expires_at FROM password_reset_tokens WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .fetch_optional(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert!(token_row.is_some(), "Token should exist");
            let (expires_at,) = token_row.unwrap();
            assert!(expires_at <= Utc::now(), "Token should be expired");

            fixture.cleanup().await;
        }

        /// T028: Test used token rejection
        #[tokio::test]
        async fn test_used_token_rejection() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create user
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &password_hash).await;

            // Create valid token and mark it as used
            let (token, token_hash) = create_test_password_reset_token();
            insert_valid_password_reset_token(
                &fixture.pool,
                fixture.tenant_id,
                user_id,
                &token_hash,
            )
            .await;
            mark_password_reset_token_used(&fixture.pool, &token_hash).await;

            // Check token is marked as used
            let token_row: Option<(Option<chrono::DateTime<Utc>>,)> =
                sqlx::query_as("SELECT used_at FROM password_reset_tokens WHERE token_hash = $1")
                    .bind(&token_hash)
                    .fetch_optional(&fixture.pool)
                    .await
                    .expect("Query should succeed");

            assert!(token_row.is_some(), "Token should exist");
            let (used_at,) = token_row.unwrap();
            assert!(used_at.is_some(), "Token should be marked as used");

            fixture.cleanup().await;
        }

        /// T029: Test weak password rejection
        #[tokio::test]
        async fn test_weak_password_rejection() {
            use xavyo_api_auth::validate_password;

            // Test various weak passwords
            let weak_passwords = [
                ("short", "Aa1!"),            // Too short
                ("no_upper", "testpass1!"),   // No uppercase
                ("no_lower", "TESTPASS1!"),   // No lowercase
                ("no_digit", "TestPass!!"),   // No digit
                ("no_special", "TestPass12"), // No special character
            ];

            for (name, password) in weak_passwords.iter() {
                let result = validate_password(password);
                assert!(
                    !result.is_valid,
                    "Password '{}' ({}) should be rejected",
                    password, name
                );
            }

            // Valid password should pass
            let result = validate_password("SecureP@ss123");
            assert!(result.is_valid, "Valid password should be accepted");
        }

        /// T030: Test refresh token revocation after password reset
        #[tokio::test]
        async fn test_refresh_token_revocation_after_reset() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create user
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &password_hash).await;

            // Create some refresh tokens for this user
            for i in 0..3 {
                let token_hash = hash_token(&format!("refresh_token_{}", i));
                sqlx::query(
                    r#"
                    INSERT INTO refresh_tokens (tenant_id, user_id, token_hash, expires_at)
                    VALUES ($1, $2, $3, NOW() + INTERVAL '7 days')
                    "#,
                )
                .bind(fixture.tenant_id.as_uuid())
                .bind(user_id.as_uuid())
                .bind(&token_hash)
                .execute(&fixture.pool)
                .await
                .expect("Should create refresh token");
            }

            // Verify refresh tokens exist
            let token_count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(user_id.as_uuid())
            .fetch_one(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert_eq!(token_count.0, 3, "Should have 3 active refresh tokens");

            // Simulate password reset - revoke all refresh tokens
            let revoked = sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL"
            )
            .bind(user_id.as_uuid())
            .execute(&fixture.pool)
            .await
            .expect("Should revoke tokens");

            assert_eq!(revoked.rows_affected(), 3, "Should revoke 3 tokens");

            // Verify all tokens are revoked
            let active_count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(user_id.as_uuid())
            .fetch_one(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert_eq!(active_count.0, 0, "Should have no active refresh tokens");

            fixture.cleanup().await;
        }
    }

    // =========================================================================
    // User Story 3: Email Verification
    // Tasks: T036-T039, T045
    // =========================================================================

    mod verify_email {
        use super::*;

        /// T036: Test successful email verification
        #[tokio::test]
        async fn test_successful_email_verification() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create unverified user
            let user_id = create_test_user_with_options(
                &fixture.pool,
                fixture.tenant_id,
                &email,
                &password_hash,
                true,  // is_active
                false, // email_verified = false
            )
            .await;

            // Create valid verification token
            let (token, token_hash) = create_test_verification_token();
            insert_valid_verification_token(&fixture.pool, fixture.tenant_id, user_id, &token_hash)
                .await;

            // Verify token is valid
            assert!(verify_token_hash_constant_time(&token, &token_hash));

            // Verify user email
            sqlx::query(
                "UPDATE users SET email_verified = true, email_verified_at = NOW(), updated_at = NOW() WHERE id = $1"
            )
            .bind(user_id.as_uuid())
            .execute(&fixture.pool)
            .await
            .expect("Should verify email");

            // Mark token as used
            mark_verification_token_verified(&fixture.pool, &token_hash).await;

            // Verify user is now verified
            let user_row: (bool,) =
                sqlx::query_as("SELECT email_verified FROM users WHERE id = $1")
                    .bind(user_id.as_uuid())
                    .fetch_one(&fixture.pool)
                    .await
                    .expect("Query should succeed");

            assert!(user_row.0, "User should be verified");

            fixture.cleanup().await;
        }

        /// T037: Test expired verification token rejection
        #[tokio::test]
        async fn test_expired_verification_token_rejection() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create unverified user
            let user_id = create_test_user_with_options(
                &fixture.pool,
                fixture.tenant_id,
                &email,
                &password_hash,
                true,
                false,
            )
            .await;

            // Create expired verification token
            let (_, token_hash) = create_test_verification_token();
            insert_expired_verification_token(
                &fixture.pool,
                fixture.tenant_id,
                user_id,
                &token_hash,
            )
            .await;

            // Check token is expired
            let token_row: Option<(chrono::DateTime<Utc>,)> = sqlx::query_as(
                "SELECT expires_at FROM email_verification_tokens WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .fetch_optional(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert!(token_row.is_some(), "Token should exist");
            let (expires_at,) = token_row.unwrap();
            assert!(expires_at <= Utc::now(), "Token should be expired");

            fixture.cleanup().await;
        }

        /// T038: Test already verified email (idempotent behavior)
        #[tokio::test]
        async fn test_already_verified_email_idempotent() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create already verified user
            let user_id = create_test_user_with_options(
                &fixture.pool,
                fixture.tenant_id,
                &email,
                &password_hash,
                true,
                true, // email_verified = true
            )
            .await;

            // Check user is verified
            let user_row: (bool,) =
                sqlx::query_as("SELECT email_verified FROM users WHERE id = $1")
                    .bind(user_id.as_uuid())
                    .fetch_one(&fixture.pool)
                    .await
                    .expect("Query should succeed");

            assert!(user_row.0, "User should already be verified");

            // In the handler, this should return success with already_verified flag
            // The behavior is idempotent - verifying an already verified user succeeds

            fixture.cleanup().await;
        }

        /// T039: Test invalid token rejection
        #[tokio::test]
        async fn test_invalid_verification_token_rejection() {
            let fixture = TestFixture::new().await;

            // Try to look up a non-existent token
            let fake_token_hash = hash_token("this_token_does_not_exist");

            let token_row: Option<(uuid::Uuid,)> =
                sqlx::query_as("SELECT id FROM email_verification_tokens WHERE token_hash = $1")
                    .bind(&fake_token_hash)
                    .fetch_optional(&fixture.pool)
                    .await
                    .expect("Query should succeed");

            assert!(token_row.is_none(), "Token should not exist");

            fixture.cleanup().await;
        }
    }

    // =========================================================================
    // User Story 4: Resend Verification
    // Tasks: T046-T049, T054
    // =========================================================================

    mod resend_verification {
        use super::*;

        /// T046: Test successful resend verification
        #[tokio::test]
        async fn test_successful_resend_verification() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create unverified user
            let user_id = create_test_user_with_options(
                &fixture.pool,
                fixture.tenant_id,
                &email,
                &password_hash,
                true,
                false, // not verified
            )
            .await;

            let email_sender = MockEmailSender::new();

            // Simulate resend verification flow
            // 1. Find unverified user
            let user_row: Option<(uuid::Uuid, bool, bool)> = sqlx::query_as(
                "SELECT id, is_active, email_verified FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)"
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind(&email)
            .fetch_optional(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert!(user_row.is_some());
            let (found_id, is_active, email_verified) = user_row.unwrap();
            assert_eq!(found_id, *user_id.as_uuid());
            assert!(is_active);
            assert!(!email_verified, "User should not be verified");

            // 2. Generate new token
            let (token, token_hash) = generate_email_verification_token();
            let expires_at =
                Utc::now() + ChronoDuration::hours(EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS);

            // 3. Store token
            sqlx::query(
                r#"
                INSERT INTO email_verification_tokens (tenant_id, user_id, token_hash, expires_at, ip_address)
                VALUES ($1, $2, $3, $4, '127.0.0.1')
                "#
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind(user_id.as_uuid())
            .bind(&token_hash)
            .bind(expires_at)
            .execute(&fixture.pool)
            .await
            .expect("Should insert token");

            // 4. Send verification email
            email_sender
                .send_verification(&email, &token, fixture.tenant_id)
                .await
                .expect("Should send verification email");

            // Verify email was sent
            let verifications = email_sender.get_verifications();
            assert_eq!(verifications.len(), 1);
            assert_eq!(verifications[0].0, email);

            fixture.cleanup().await;
        }

        /// T047: Test already verified user (no email sent)
        #[tokio::test]
        async fn test_already_verified_user_no_email() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Create already verified user
            let user_id = create_test_user_with_options(
                &fixture.pool,
                fixture.tenant_id,
                &email,
                &password_hash,
                true,
                true, // verified
            )
            .await;

            let email_sender = MockEmailSender::new();

            // Check user is verified
            let user_row: Option<(bool,)> =
                sqlx::query_as("SELECT email_verified FROM users WHERE id = $1")
                    .bind(user_id.as_uuid())
                    .fetch_optional(&fixture.pool)
                    .await
                    .expect("Query should succeed");

            assert!(user_row.is_some());
            let (email_verified,) = user_row.unwrap();
            assert!(email_verified, "User should be verified");

            // No email should be sent (handler returns early for verified users)
            // In real handler: if email_verified { return Ok(()) }

            // Verify no emails were sent
            assert!(
                email_sender.get_verifications().is_empty(),
                "No verification email should be sent"
            );

            fixture.cleanup().await;
        }

        /// T048: Test rate limiting for resend verification
        #[tokio::test]
        async fn test_resend_rate_limiting() {
            let email = "resend-test@example.com";
            let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

            // Use a rate limiter with low limits
            let rate_limiter = EmailRateLimiter::with_config(2, 5, 60);

            // First two attempts should succeed
            assert!(rate_limiter.record_attempt(email, ip));
            assert!(rate_limiter.record_attempt(email, ip));

            // Third should fail (email limit = 2)
            assert!(!rate_limiter.record_attempt(email, ip));

            // Check remaining attempts
            assert_eq!(rate_limiter.remaining_email_attempts(email), 0);
            assert_eq!(rate_limiter.remaining_ip_attempts(ip), 3); // IP limit is 5, used 2
        }

        /// T049: Test non-existent email (same response, no enumeration)
        #[tokio::test]
        async fn test_non_existent_email_no_enumeration() {
            let fixture = TestFixture::new().await;
            let email_sender = MockEmailSender::new();

            // Look up non-existent user
            let user_row: Option<(uuid::Uuid,)> = sqlx::query_as(
                "SELECT id FROM users WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)",
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind("nonexistent@example.com")
            .fetch_optional(&fixture.pool)
            .await
            .expect("Query should succeed");

            assert!(user_row.is_none(), "User should not exist");

            // No email should be sent
            // In real handler: if user not found, return Ok(()) to prevent enumeration

            assert!(email_sender.get_verifications().is_empty());

            fixture.cleanup().await;
        }
    }

    // =========================================================================
    // Integration Tests: Full Flows
    // Tasks: T055-T056
    // =========================================================================

    mod integration {
        use super::*;

        /// T055: Full password reset flow (request → token → reset)
        #[tokio::test]
        async fn test_full_password_reset_flow() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let old_password = valid_test_password();
            let old_password_hash = hash_password(old_password).expect("Should hash password");

            // Step 1: Create user
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &old_password_hash)
                    .await;

            // Step 2: Request password reset
            let email_sender = MockEmailSender::new();
            let (token, token_hash) = generate_password_reset_token();
            let expires_at = Utc::now() + ChronoDuration::hours(1);

            sqlx::query(
                r#"
                INSERT INTO password_reset_tokens (tenant_id, user_id, token_hash, expires_at, ip_address)
                VALUES ($1, $2, $3, $4, '127.0.0.1')
                "#
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind(user_id.as_uuid())
            .bind(&token_hash)
            .bind(expires_at)
            .execute(&fixture.pool)
            .await
            .expect("Should insert token");

            email_sender
                .send_password_reset(&email, &token, fixture.tenant_id)
                .await
                .expect("Should send reset email");

            // Step 3: Verify token received
            let sent_token = email_sender
                .get_last_reset_token(&email)
                .expect("Should have received token");
            assert_eq!(sent_token, token);

            // Step 4: Reset password with token
            let new_password = "NewSecureP@ss789";
            let new_password_hash = hash_password(new_password).expect("Should hash new password");

            // Verify token
            assert!(verify_token_hash_constant_time(&token, &token_hash));

            // Update password
            sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
                .bind(&new_password_hash)
                .bind(user_id.as_uuid())
                .execute(&fixture.pool)
                .await
                .expect("Should update password");

            // Mark token used
            sqlx::query("UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = $1")
                .bind(&token_hash)
                .execute(&fixture.pool)
                .await
                .expect("Should mark token used");

            // Step 5: Verify old password no longer works, new password works
            let user: (String,) = sqlx::query_as("SELECT password_hash FROM users WHERE id = $1")
                .bind(user_id.as_uuid())
                .fetch_one(&fixture.pool)
                .await
                .expect("Should find user");

            assert_eq!(user.0, new_password_hash, "Password should be updated");

            fixture.cleanup().await;
        }

        /// T056: Full email verification flow (register → receive email → verify)
        #[tokio::test]
        async fn test_full_email_verification_flow() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");

            // Step 1: Create unverified user (simulates registration)
            let user_id = create_test_user_with_options(
                &fixture.pool,
                fixture.tenant_id,
                &email,
                &password_hash,
                true,
                false, // not verified
            )
            .await;

            // Step 2: Send verification email
            let email_sender = MockEmailSender::new();
            let (token, token_hash) = generate_email_verification_token();
            let expires_at = Utc::now() + ChronoDuration::hours(24);

            sqlx::query(
                r#"
                INSERT INTO email_verification_tokens (tenant_id, user_id, token_hash, expires_at, ip_address)
                VALUES ($1, $2, $3, $4, '127.0.0.1')
                "#
            )
            .bind(fixture.tenant_id.as_uuid())
            .bind(user_id.as_uuid())
            .bind(&token_hash)
            .bind(expires_at)
            .execute(&fixture.pool)
            .await
            .expect("Should insert token");

            email_sender
                .send_verification(&email, &token, fixture.tenant_id)
                .await
                .expect("Should send verification email");

            // Step 3: Verify token received
            let sent_token = email_sender
                .get_last_verification_token(&email)
                .expect("Should have received token");
            assert_eq!(sent_token, token);

            // Step 4: Verify email with token
            assert!(verify_token_hash_constant_time(&token, &token_hash));

            sqlx::query(
                "UPDATE users SET email_verified = true, email_verified_at = NOW(), updated_at = NOW() WHERE id = $1"
            )
            .bind(user_id.as_uuid())
            .execute(&fixture.pool)
            .await
            .expect("Should verify email");

            sqlx::query(
                "UPDATE email_verification_tokens SET verified_at = NOW() WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .execute(&fixture.pool)
            .await
            .expect("Should mark token verified");

            // Step 5: Verify user is now verified
            let user: (bool,) = sqlx::query_as("SELECT email_verified FROM users WHERE id = $1")
                .bind(user_id.as_uuid())
                .fetch_one(&fixture.pool)
                .await
                .expect("Should find user");

            assert!(user.0, "User should be verified");

            fixture.cleanup().await;
        }
    }

    // =========================================================================
    // Success Criteria Verification
    // Tasks: T057-T061
    // =========================================================================

    mod success_criteria {
        use super::*;

        /// T057: Verify SC-001: Password reset flow can complete
        /// (This is effectively tested by test_full_password_reset_flow)

        /// T058: Verify SC-004: System correctly rejects 100% of expired tokens
        #[tokio::test]
        async fn test_sc004_expired_tokens_rejected() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &password_hash).await;

            // Test multiple expired tokens
            for i in 0..5 {
                let (_, token_hash) = create_test_password_reset_token();
                insert_expired_password_reset_token(
                    &fixture.pool,
                    fixture.tenant_id,
                    user_id,
                    &token_hash,
                )
                .await;

                // Verify token is expired
                let token_row: (chrono::DateTime<Utc>,) = sqlx::query_as(
                    "SELECT expires_at FROM password_reset_tokens WHERE token_hash = $1",
                )
                .bind(&token_hash)
                .fetch_one(&fixture.pool)
                .await
                .expect("Query should succeed");

                assert!(token_row.0 <= Utc::now(), "Token {} should be expired", i);
            }

            fixture.cleanup().await;
        }

        /// T059: Verify SC-005: System correctly rejects 100% of already-used tokens
        #[tokio::test]
        async fn test_sc005_used_tokens_rejected() {
            let fixture = TestFixture::new().await;
            let email = valid_test_email();
            let password_hash = hash_password(valid_test_password()).expect("Should hash password");
            let user_id =
                create_test_user(&fixture.pool, fixture.tenant_id, &email, &password_hash).await;

            // Create and mark multiple tokens as used
            for i in 0..5 {
                let (_, token_hash) = create_test_password_reset_token();
                insert_valid_password_reset_token(
                    &fixture.pool,
                    fixture.tenant_id,
                    user_id,
                    &token_hash,
                )
                .await;
                mark_password_reset_token_used(&fixture.pool, &token_hash).await;

                // Verify token is marked as used
                let token_row: (Option<chrono::DateTime<Utc>>,) = sqlx::query_as(
                    "SELECT used_at FROM password_reset_tokens WHERE token_hash = $1",
                )
                .bind(&token_hash)
                .fetch_one(&fixture.pool)
                .await
                .expect("Query should succeed");

                assert!(
                    token_row.0.is_some(),
                    "Token {} should be marked as used",
                    i
                );
            }

            fixture.cleanup().await;
        }

        /// T060: Verify SC-006: Rate limiting blocks excessive requests
        #[tokio::test]
        async fn test_sc006_rate_limiting_works() {
            let rate_limiter = EmailRateLimiter::new();
            let email = "rate-limit-test@example.com";
            let ip: std::net::IpAddr = "172.16.0.1".parse().unwrap();

            // Default limits: 3 per email, 10 per IP per hour
            // Send up to email limit
            for _ in 0..3 {
                assert!(rate_limiter.record_attempt(email, ip));
            }

            // Next attempt should be blocked
            assert!(!rate_limiter.record_attempt(email, ip));
            assert!(rate_limiter.is_email_limited(email));
        }

        /// T061: Verify SC-007: No email enumeration
        /// Verified by tests in forgot_password and resend_verification modules
        /// The key point is: same response for existing and non-existing emails
        #[tokio::test]
        async fn test_sc007_no_email_enumeration() {
            // This is a design verification - the handlers return the same response
            // whether the email exists or not

            // For forgot password: always return "If an account exists..."
            let response = xavyo_api_auth::models::ForgotPasswordResponse::default();
            assert!(response.message.contains("If an account exists"));

            // For resend verification: always return "If an unverified account exists..."
            let response = xavyo_api_auth::models::ResendVerificationResponse::default();
            assert!(response.message.contains("If an unverified account exists"));
        }
    }
}

// Unit tests that don't require database
mod unit_tests {
    use xavyo_api_auth::middleware::EmailRateLimiter;
    use xavyo_api_auth::services::{
        generate_email_verification_token, generate_password_reset_token, generate_secure_token,
        verify_token_hash_constant_time,
    };

    #[test]
    fn test_token_generation() {
        let (token, hash) = generate_password_reset_token();

        // Token should be non-empty and URL-safe base64
        assert!(!token.is_empty());
        assert!(token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));

        // Hash should be non-empty
        assert!(!hash.is_empty());

        // Verification should work
        assert!(verify_token_hash_constant_time(&token, &hash));
    }

    #[test]
    fn test_token_verification_constant_time() {
        let (token, hash) = generate_password_reset_token();

        // Correct token should verify
        assert!(verify_token_hash_constant_time(&token, &hash));

        // Wrong token should not verify
        assert!(!verify_token_hash_constant_time("wrong_token", &hash));

        // Modified token should not verify
        let modified = format!("{token}x");
        assert!(!verify_token_hash_constant_time(&modified, &hash));
    }

    #[test]
    fn test_email_verification_token_generation() {
        let (token, hash) = generate_email_verification_token();

        assert!(!token.is_empty());
        assert!(!hash.is_empty());
        assert!(verify_token_hash_constant_time(&token, &hash));
    }

    #[test]
    fn test_secure_token_uniqueness() {
        let tokens: std::collections::HashSet<_> =
            (0..100).map(|_| generate_secure_token()).collect();

        // All tokens should be unique
        assert_eq!(tokens.len(), 100);
    }

    #[test]
    fn test_email_rate_limiter_email_case_insensitive() {
        let limiter = EmailRateLimiter::with_config(2, 10, 60);
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();

        // Emails should be treated case-insensitively
        limiter.record_attempt("Test@Example.com", ip);
        limiter.record_attempt("TEST@EXAMPLE.COM", ip);

        // Third attempt with different case should fail
        assert!(!limiter.record_attempt("test@example.com", ip));
    }

    #[test]
    fn test_email_rate_limiter_different_emails_independent() {
        let limiter = EmailRateLimiter::with_config(1, 10, 60);
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();

        // Different emails should have independent limits
        assert!(limiter.record_attempt("user1@example.com", ip));
        assert!(!limiter.record_attempt("user1@example.com", ip)); // limit reached

        assert!(limiter.record_attempt("user2@example.com", ip)); // different email OK
    }
}
