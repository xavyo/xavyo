//! Integration tests for xavyo-api-auth.
//!
//! These tests require a running `PostgreSQL` database with the test schema.
//! Run with: `cargo test -p xavyo-api-auth --features integration`

mod common;

#[cfg(feature = "integration")]
mod integration_tests {
    use super::common::*;
    use xavyo_api_auth::{AuthService, TokenConfig, TokenService};
    use xavyo_core::TenantId;

    // Test RSA key pair for JWT signing (test only)
    const TEST_PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC46zZuOStUrVWL
q5KtkAaPL9hNCULR4zPhgskdUOB1c+bxRiOicEHKTBsqb4LSnizIb3fIEN5XuUL5
TzOBKT3hAc/gKKU71VKE5EMcbfuLLVxTqj08K2j7PzCChzzydZGjAWfisndASeQP
IJ1HM3Lh3VhXar3uwxbpT2Kqx59C7SDpCTHsZwvLVMupyEiL+18rFI7vDvlnHxuo
G5dkGZhyZrLfKx1A3eX49UibiJz8Km4UtbReZ5O+VSndHYmhLFXJKHd9pOr7Xxyy
mTucGJbmZOmSjb3bgaIhYyH+CtpoxTtqCfUi2kHCZdC1cGF93UnqLmNIq7nc0Ybh
JJc++72NAgMBAAECggEAA4ZeSP8Xe5t7PjiUyPCuI1QY5i0HREt1rXaKAWBNiwec
zxwUaVAE/Qdy3B34iy2/MknnqV1i856hL3HqTCu+VXfsn7v+nFOeaVCVk+jnytkg
QasE1E0KiQGFGfPcfk2t60LHWWun+MZ/zacEQHtzVOlcefwbpz26RdPA0HsSJtso
cqgiF274eoWfzOqWvGxmbPwvToVVb+PPRw8r1+EcQ95vaWM24O83/lfVNmUgonzD
S7qqRq3g51enCHBuoqE2a9tIx3UGut/MP5MECxdgw+bfcOAZ1z7hzai5difHF/vr
amWytmlPdJJIvYeKU7H4YISmYQUQ8JB9fGCMMeX1+QKBgQD1iyJy4RFDBL3Izl5b
p2vyu1GkUiJw7dz8F1MTrz25uRnMdyqvkV6X9u8uw7BzQ7D9ecTPrJrHlvaLeISP
RR/4EfjY9wC5VrEpwrrKYaf12DGqhVyTpwktrVgUkUmOXSTi8256DkOwuR3QgIhD
Cbkvq6iwHEhIxLzv8iApVsDt+QKBgQDAyyjvzWJnsew+iFcXqwAPRXkv1bXGrFYE
iub3K5HqGe6G2JS89dEvqqjmne9qZshG9M7FyHapX8NdKE5e6a5mADLr4thpMqJY
gKTi1gs4vlq55ziz5LW3gYLbPkp+P8bKBzVa/M/457oudHpPR4+EwVwsP4I9YCAO
EoNqYiCBNQKBgQCCc1Lv+Yb0NhamEo2q3/3HzaEITeKiYJzhCXtHn/iJLT/5ku4I
rJC256gXDjw2YKYtZH4dXzQ0CY4edv7mJvFfGB0/F6s4zEf/Scd3Mf7L6/onAAc5
IqsLq2Z6Nt3/Vpj8QhxVmDJ6Nz8RwNej1gyeuPI77iqxDmTajaZsj/yb8QKBgQCR
K2kTyI9EjZDaNUd/Jt/Qn/t0rXNGuhW7LexkSYaBxCz7lLHK5z4wqkyr+liAwgwk
gcoA28WeG+G7j9ITXdpYK+YsAI/8BoiAI74EoC+q9orSWO01aA38s6SY+fqVvegt
z+e5L4xaXAKxYDuI3tWOnRqOpvOmy27XqdESlfjr0QKBgDpS1FtG9JN1Bg01GoOp
Hzl/YpRraobBYDOtv70uNx9QyKAeFmvhDkwmgbOA1efFMgcPG7bdvL5ld7/N6d7D
RSiBP/6TepaXLEdSsrN4dARjpDeuV87IokbrVay54JWW0yTStzAzbLFcodp3sBNn
6iYwOxn6PHzksnM+GSuHzWGz
-----END PRIVATE KEY-----"#;

    // =========================================================================
    // Phase 3: User Story 1 - Registration Tests
    // =========================================================================

    mod registration {
        use super::*;

        /// T017: Test successful registration
        #[tokio::test]
        async fn test_successful_registration() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            let result = auth_service
                .register(fixture.tenant_id, &email, password)
                .await;

            assert!(result.is_ok(), "Registration should succeed");
            let (user_id, returned_email, created_at) = result.unwrap();
            assert_eq!(returned_email, email.to_lowercase());
            assert!(created_at <= chrono::Utc::now());

            fixture.cleanup().await;
        }

        /// T018: Test duplicate email rejection
        #[tokio::test]
        async fn test_duplicate_email_rejection() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // First registration should succeed
            let first = auth_service
                .register(fixture.tenant_id, &email, password)
                .await;
            assert!(first.is_ok());

            // Second registration with same email should fail
            let second = auth_service
                .register(fixture.tenant_id, &email, password)
                .await;

            assert!(second.is_err());
            match second.unwrap_err() {
                xavyo_api_auth::ApiAuthError::EmailInUse => {}
                other => panic!("Expected EmailInUse error, got {:?}", other),
            }

            fixture.cleanup().await;
        }

        /// T019: Test weak password rejection
        #[tokio::test]
        async fn test_weak_password_rejection() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());

            let email = valid_test_email();

            // Too short
            let result = auth_service
                .register(fixture.tenant_id, &email, invalid_test_password_short())
                .await;
            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::WeakPassword(errors) => {
                    assert!(!errors.is_empty());
                }
                other => panic!("Expected WeakPassword error, got {:?}", other),
            }

            // Missing special char
            let result = auth_service
                .register(
                    fixture.tenant_id,
                    &email,
                    invalid_test_password_no_special(),
                )
                .await;
            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::WeakPassword(errors) => {
                    assert!(errors.iter().any(|e| e.contains("special")));
                }
                other => panic!("Expected WeakPassword error, got {:?}", other),
            }

            fixture.cleanup().await;
        }

        /// T020: Test invalid email rejection
        #[tokio::test]
        async fn test_invalid_email_rejection() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());

            let result = auth_service
                .register(
                    fixture.tenant_id,
                    invalid_test_email(),
                    valid_test_password(),
                )
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::InvalidEmail(msg) => {
                    assert!(!msg.is_empty());
                }
                other => panic!("Expected InvalidEmail error, got {:?}", other),
            }

            fixture.cleanup().await;
        }
    }

    // =========================================================================
    // Phase 4: User Story 2 - Login Tests
    // =========================================================================

    mod login {
        use super::*;

        /// T025: Test successful login returns tokens
        #[tokio::test]
        async fn test_successful_login() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // Register first
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, password)
                .await
                .expect("Registration should succeed");

            // Verify email (required for login)
            set_user_email_verified(&fixture.pool, user_id, true).await;

            // Login
            let result = auth_service
                .login(fixture.tenant_id, &email, password)
                .await;

            assert!(result.is_ok(), "Login should succeed");
            let user = result.unwrap();
            assert_eq!(user.email, email.to_lowercase());
            assert!(user.is_active);

            fixture.cleanup().await;
        }

        /// T026: Test invalid credentials returns generic error
        #[tokio::test]
        async fn test_invalid_credentials() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());

            let email = valid_test_email();

            // Register first
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, valid_test_password())
                .await
                .expect("Registration should succeed");

            // Verify email (required for login to check credentials)
            set_user_email_verified(&fixture.pool, user_id, true).await;

            // Login with wrong password
            let result = auth_service
                .login(fixture.tenant_id, &email, "WrongP@ss123")
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::InvalidCredentials => {}
                other => panic!("Expected InvalidCredentials error, got {:?}", other),
            }

            fixture.cleanup().await;
        }

        /// T027: Rate limiting is tested via middleware, not here
        /// See middleware/rate_limit.rs for rate limit unit tests

        /// T028: Test inactive account rejection
        #[tokio::test]
        async fn test_inactive_account_rejection() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // Register
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, password)
                .await
                .expect("Registration should succeed");

            // Deactivate user directly in database
            sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
                .bind(user_id.as_uuid())
                .execute(&fixture.pool)
                .await
                .expect("Should deactivate user");

            // Login should fail
            let result = auth_service
                .login(fixture.tenant_id, &email, password)
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::AccountInactive => {}
                other => panic!("Expected AccountInactive error, got {:?}", other),
            }

            fixture.cleanup().await;
        }
    }

    // =========================================================================
    // Phase 5: User Story 3 - Token Refresh Tests
    // =========================================================================

    mod refresh {
        use super::*;

        fn create_token_config() -> TokenConfig {
            TokenConfig {
                private_key: TEST_PRIVATE_KEY.to_vec(),
                issuer: "xavyo-test".to_string(),
                audience: "xavyo-test".to_string(),
            }
        }

        /// T034: Test successful token refresh
        #[tokio::test]
        async fn test_successful_token_refresh() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());
            let token_service = TokenService::new(create_token_config(), fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // Register and verify email
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, password)
                .await
                .expect("Registration should succeed");
            set_user_email_verified(&fixture.pool, user_id, true).await;

            let user = auth_service
                .login(fixture.tenant_id, &email, password)
                .await
                .expect("Login should succeed");

            // Create initial tokens
            let (_, refresh_token, _) = token_service
                .create_tokens(
                    user.user_id(),
                    user.tenant_id(),
                    vec!["user".to_string()],
                    None,
                    None,
                )
                .await
                .expect("Token creation should succeed");

            // Refresh
            let result = token_service
                .refresh_tokens(&refresh_token, None, None)
                .await;

            assert!(result.is_ok(), "Token refresh should succeed");
            let (new_access, new_refresh, _) = result.unwrap();
            assert!(!new_access.is_empty());
            assert!(!new_refresh.is_empty());
            assert_ne!(
                new_refresh, refresh_token,
                "New refresh token should be different"
            );

            fixture.cleanup().await;
        }

        /// T035: Test expired refresh token rejection
        /// Note: This requires manipulating the database to set expired time

        /// T036: Test revoked refresh token rejection
        #[tokio::test]
        async fn test_revoked_token_rejection() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());
            let token_service = TokenService::new(create_token_config(), fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // Register and verify email
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, password)
                .await
                .expect("Registration should succeed");
            set_user_email_verified(&fixture.pool, user_id, true).await;

            let user = auth_service
                .login(fixture.tenant_id, &email, password)
                .await
                .expect("Login should succeed");

            // Create tokens
            let (_, refresh_token, _) = token_service
                .create_tokens(
                    user.user_id(),
                    user.tenant_id(),
                    vec!["user".to_string()],
                    None,
                    None,
                )
                .await
                .expect("Token creation should succeed");

            // Revoke the token
            token_service
                .revoke_token(&refresh_token)
                .await
                .expect("Revocation should succeed");

            // Attempt to refresh
            let result = token_service
                .refresh_tokens(&refresh_token, None, None)
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::TokenRevoked => {}
                other => panic!("Expected TokenRevoked error, got {:?}", other),
            }

            fixture.cleanup().await;
        }

        /// T037: Test inactive user refresh rejection
        #[tokio::test]
        async fn test_inactive_user_refresh_rejection() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());
            let token_service = TokenService::new(create_token_config(), fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // Register and verify email
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, password)
                .await
                .expect("Registration should succeed");
            set_user_email_verified(&fixture.pool, user_id, true).await;

            let user = auth_service
                .login(fixture.tenant_id, &email, password)
                .await
                .expect("Login should succeed");

            // Create tokens
            let (_, refresh_token, _) = token_service
                .create_tokens(
                    user.user_id(),
                    user.tenant_id(),
                    vec!["user".to_string()],
                    None,
                    None,
                )
                .await
                .expect("Token creation should succeed");

            // Deactivate user
            sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
                .bind(user.id)
                .execute(&fixture.pool)
                .await
                .expect("Should deactivate user");

            // Attempt to refresh
            let result = token_service
                .refresh_tokens(&refresh_token, None, None)
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::AccountInactive => {}
                other => panic!("Expected AccountInactive error, got {:?}", other),
            }

            fixture.cleanup().await;
        }
    }

    // =========================================================================
    // Phase 6: User Story 4 - Logout Tests
    // =========================================================================

    mod logout {
        use super::*;

        fn create_token_config() -> TokenConfig {
            TokenConfig {
                private_key: TEST_PRIVATE_KEY.to_vec(),
                issuer: "xavyo-test".to_string(),
                audience: "xavyo-test".to_string(),
            }
        }

        /// T043: Test successful logout
        #[tokio::test]
        async fn test_successful_logout() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());
            let token_service = TokenService::new(create_token_config(), fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // Register and verify email
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, password)
                .await
                .expect("Registration should succeed");
            set_user_email_verified(&fixture.pool, user_id, true).await;

            let user = auth_service
                .login(fixture.tenant_id, &email, password)
                .await
                .expect("Login should succeed");

            // Create tokens
            let (_, refresh_token, _) = token_service
                .create_tokens(
                    user.user_id(),
                    user.tenant_id(),
                    vec!["user".to_string()],
                    None,
                    None,
                )
                .await
                .expect("Token creation should succeed");

            // Logout (revoke token)
            let result = token_service.revoke_token(&refresh_token).await;
            assert!(result.is_ok(), "Logout should succeed");

            fixture.cleanup().await;
        }

        /// T044: Test refresh token invalidation after logout
        #[tokio::test]
        async fn test_token_invalid_after_logout() {
            let fixture = TestFixture::new().await;
            let auth_service = AuthService::new(fixture.pool.clone());
            let token_service = TokenService::new(create_token_config(), fixture.pool.clone());

            let email = valid_test_email();
            let password = valid_test_password();

            // Register and verify email
            let (user_id, _, _) = auth_service
                .register(fixture.tenant_id, &email, password)
                .await
                .expect("Registration should succeed");
            set_user_email_verified(&fixture.pool, user_id, true).await;

            let user = auth_service
                .login(fixture.tenant_id, &email, password)
                .await
                .expect("Login should succeed");

            // Create tokens
            let (_, refresh_token, _) = token_service
                .create_tokens(
                    user.user_id(),
                    user.tenant_id(),
                    vec!["user".to_string()],
                    None,
                    None,
                )
                .await
                .expect("Token creation should succeed");

            // Logout
            token_service
                .revoke_token(&refresh_token)
                .await
                .expect("Logout should succeed");

            // Try to use the revoked token
            let result = token_service
                .refresh_tokens(&refresh_token, None, None)
                .await;

            assert!(result.is_err());
            match result.unwrap_err() {
                xavyo_api_auth::ApiAuthError::TokenRevoked => {}
                other => panic!("Expected TokenRevoked error, got {:?}", other),
            }

            fixture.cleanup().await;
        }
    }
}

// Unit tests that don't require database
mod unit_tests {
    use xavyo_api_auth::{validate_email, validate_password};

    #[test]
    fn test_password_validation() {
        // Valid password
        let result = validate_password("SecureP@ss1");
        assert!(result.is_valid);

        // Too short
        let result = validate_password("Aa1!");
        assert!(!result.is_valid);

        // Missing special char
        let result = validate_password("SecurePass1");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_email_validation() {
        // Valid email
        let result = validate_email("test@example.com");
        assert!(result.is_valid);

        // Invalid email
        let result = validate_email("not-an-email");
        assert!(!result.is_valid);
    }
}
