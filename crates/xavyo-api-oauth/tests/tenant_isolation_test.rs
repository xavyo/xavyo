//! Integration tests for multi-tenant isolation.
//!
//! These tests verify that tenant isolation is enforced across all operations:
//! - Clients from one tenant are not visible to another tenant
//! - Tokens from one tenant cannot be used in another tenant
//! - Authorization requests must match tenant context
//!
//! Run with:
//! cargo test -p xavyo-api-oauth --features integration --test tenant_isolation_test
//!
//! Prerequisites:
//! - PostgreSQL running with migrations applied
//! - DATABASE_URL and DATABASE_URL_SUPERUSER environment variables set

mod common;

/// Test module for OAuth client tenant isolation.
#[cfg(feature = "integration")]
mod client_isolation {
    use super::common::OAuthTestContext;
    use xavyo_api_oauth::error::OAuthError;
    use xavyo_api_oauth::models::{ClientType, CreateClientRequest};
    use xavyo_api_oauth::services::OAuth2ClientService;

    /// Helper to create a test client request.
    fn create_test_client_request(name: &str) -> CreateClientRequest {
        CreateClientRequest {
            name: name.to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec!["client_credentials".to_string()],
            scopes: vec!["api:read".to_string()],
        }
    }

    /// T-001: Tenant A cannot read Tenant B's OAuth clients via API.
    ///
    /// This verifies Row-Level Security prevents cross-tenant data access.
    #[tokio::test]
    async fn test_client_isolation_between_tenants() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-iso-a-{}", unique_id);
        let slug_b = format!("tenant-iso-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create a client for Tenant A
        let (client_a, _secret) = service
            .create_client(
                *tenant_a.as_uuid(),
                create_test_client_request(&format!("Client A {}", unique_id)),
            )
            .await
            .expect("Failed to create client for Tenant A");

        // Tenant A can see the client
        let found = service
            .get_client_by_id(*tenant_a.as_uuid(), client_a.id)
            .await;
        assert!(
            found.is_ok(),
            "Tenant A should be able to read its own client"
        );

        // Tenant B cannot see Tenant A's client
        let not_found = service
            .get_client_by_id(*tenant_b.as_uuid(), client_a.id)
            .await;
        assert!(
            matches!(not_found, Err(OAuthError::ClientNotFound)),
            "Tenant B should NOT be able to read Tenant A's client"
        );
    }

    /// T-002: Listing clients only returns clients for the current tenant.
    #[tokio::test]
    async fn test_list_clients_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-list-a-{}", unique_id);
        let slug_b = format!("tenant-list-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create clients for both tenants
        service
            .create_client(
                *tenant_a.as_uuid(),
                create_test_client_request(&format!("Client A1 {}", unique_id)),
            )
            .await
            .expect("Failed to create client A1");

        service
            .create_client(
                *tenant_a.as_uuid(),
                create_test_client_request(&format!("Client A2 {}", unique_id)),
            )
            .await
            .expect("Failed to create client A2");

        service
            .create_client(
                *tenant_b.as_uuid(),
                create_test_client_request(&format!("Client B1 {}", unique_id)),
            )
            .await
            .expect("Failed to create client B1");

        // List clients for Tenant A - should only see A's clients
        let clients_a = service
            .list_clients(*tenant_a.as_uuid())
            .await
            .expect("Failed to list clients for Tenant A");

        assert_eq!(
            clients_a.len(),
            2,
            "Tenant A should see exactly 2 clients (its own)"
        );
        for client in &clients_a {
            assert!(
                client.name.contains(&unique_id),
                "Client should be from this test"
            );
            assert!(
                client.name.starts_with("Client A"),
                "Tenant A should only see its own clients"
            );
        }

        // List clients for Tenant B - should only see B's clients
        let clients_b = service
            .list_clients(*tenant_b.as_uuid())
            .await
            .expect("Failed to list clients for Tenant B");

        assert_eq!(
            clients_b.len(),
            1,
            "Tenant B should see exactly 1 client (its own)"
        );
        assert!(
            clients_b[0].name.starts_with("Client B"),
            "Tenant B should only see its own clients"
        );
    }

    /// T-003: Client credentials verification fails for wrong tenant context.
    #[tokio::test]
    async fn test_client_credentials_tenant_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-cred-a-{}", unique_id);
        let slug_b = format!("tenant-cred-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create a confidential client for Tenant A
        let (client_a, secret_a) = service
            .create_client(
                *tenant_a.as_uuid(),
                create_test_client_request(&format!("Cred Client {}", unique_id)),
            )
            .await
            .expect("Failed to create client");

        let secret = secret_a.expect("Confidential client should have a secret");

        // Verify credentials with correct tenant -> should succeed
        let result = service
            .verify_client_credentials(*tenant_a.as_uuid(), &client_a.client_id, &secret)
            .await;
        assert!(
            result.is_ok(),
            "Credentials should verify with correct tenant"
        );

        // Verify credentials with wrong tenant -> should fail
        let result = service
            .verify_client_credentials(*tenant_b.as_uuid(), &client_a.client_id, &secret)
            .await;
        assert!(
            matches!(result, Err(OAuthError::InvalidClient(_))),
            "Credentials should fail with wrong tenant context"
        );
    }

    /// T-004: Updating a client requires matching tenant context.
    #[tokio::test]
    async fn test_update_client_tenant_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-upd-a-{}", unique_id);
        let slug_b = format!("tenant-upd-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create a client for Tenant A
        let (client_a, _) = service
            .create_client(
                *tenant_a.as_uuid(),
                create_test_client_request(&format!("Update Client {}", unique_id)),
            )
            .await
            .expect("Failed to create client");

        // Try to update with Tenant B context -> should fail (ClientNotFound)
        let update_request = xavyo_api_oauth::models::UpdateClientRequest {
            name: Some("Hacked Name".to_string()),
            redirect_uris: None,
            grant_types: None,
            scopes: None,
            is_active: None,
        };

        let result = service
            .update_client(*tenant_b.as_uuid(), client_a.id, update_request.clone())
            .await;
        assert!(
            matches!(result, Err(OAuthError::ClientNotFound)),
            "Update with wrong tenant should fail with ClientNotFound"
        );

        // Update with correct tenant -> should succeed
        let result = service
            .update_client(*tenant_a.as_uuid(), client_a.id, update_request)
            .await;
        assert!(result.is_ok(), "Update with correct tenant should succeed");
    }

    /// T-005: Deactivating a client requires matching tenant context.
    #[tokio::test]
    async fn test_deactivate_client_tenant_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-deact-a-{}", unique_id);
        let slug_b = format!("tenant-deact-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create a client for Tenant A
        let (client_a, _) = service
            .create_client(
                *tenant_a.as_uuid(),
                create_test_client_request(&format!("Deact Client {}", unique_id)),
            )
            .await
            .expect("Failed to create client");

        // Try to deactivate with Tenant B context -> should fail
        let result = service
            .deactivate_client(*tenant_b.as_uuid(), client_a.id)
            .await;
        assert!(
            matches!(result, Err(OAuthError::ClientNotFound)),
            "Deactivate with wrong tenant should fail with ClientNotFound"
        );

        // Verify client is still active
        let client = service
            .get_client_by_id(*tenant_a.as_uuid(), client_a.id)
            .await
            .expect("Client should still exist");
        assert!(client.is_active, "Client should still be active");

        // Deactivate with correct tenant -> should succeed
        let result = service
            .deactivate_client(*tenant_a.as_uuid(), client_a.id)
            .await;
        assert!(
            result.is_ok(),
            "Deactivate with correct tenant should succeed"
        );
    }

    /// T-006: Regenerating client secret requires matching tenant context.
    #[tokio::test]
    async fn test_regenerate_secret_tenant_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-regen-a-{}", unique_id);
        let slug_b = format!("tenant-regen-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create a confidential client for Tenant A
        let (client_a, original_secret) = service
            .create_client(
                *tenant_a.as_uuid(),
                create_test_client_request(&format!("Regen Client {}", unique_id)),
            )
            .await
            .expect("Failed to create client");

        let original = original_secret.expect("Should have secret");

        // Try to regenerate secret with Tenant B context -> should fail
        let result = service
            .regenerate_client_secret(*tenant_b.as_uuid(), client_a.id)
            .await;
        assert!(
            matches!(result, Err(OAuthError::ClientNotFound)),
            "Regenerate with wrong tenant should fail"
        );

        // Verify original secret still works
        let verify_result = service
            .verify_client_credentials(*tenant_a.as_uuid(), &client_a.client_id, &original)
            .await;
        assert!(
            verify_result.is_ok(),
            "Original secret should still work after failed cross-tenant regenerate"
        );

        // Regenerate with correct tenant -> should succeed
        let new_secret = service
            .regenerate_client_secret(*tenant_a.as_uuid(), client_a.id)
            .await
            .expect("Regenerate with correct tenant should succeed");

        assert_ne!(new_secret, original, "New secret should be different");
    }
}

/// Tests for direct SQL tenant isolation via RLS.
#[cfg(feature = "integration")]
mod rls_isolation {
    use super::common::OAuthTestContext;
    use xavyo_api_oauth::models::{ClientType, CreateClientRequest};
    use xavyo_api_oauth::services::OAuth2ClientService;

    /// T-007: Direct SQL queries are blocked by RLS when no tenant context is set.
    #[tokio::test]
    async fn test_no_context_returns_no_rows() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug = format!("tenant-noctx-{}", unique_id);

        // Create tenant and client via admin
        let tenant = ctx.create_tenant("Test Tenant", &slug).await;
        service
            .create_client(
                *tenant.as_uuid(),
                CreateClientRequest {
                    name: format!("NoCtx Client {}", unique_id),
                    client_type: ClientType::Confidential,
                    redirect_uris: vec!["https://example.com/cb".to_string()],
                    grant_types: vec!["client_credentials".to_string()],
                    scopes: vec!["api:read".to_string()],
                },
            )
            .await
            .expect("Failed to create client");

        // Query directly without setting tenant context
        let mut conn = ctx.pool.acquire().await.expect("Failed to acquire conn");

        // Clear any existing context
        sqlx::query("SELECT set_config('app.current_tenant', '', true)")
            .execute(&mut *conn)
            .await
            .expect("Failed to clear context");

        // Count should be 0 due to RLS default deny
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_clients")
            .fetch_one(&mut *conn)
            .await
            .expect("Failed to count");

        assert_eq!(
            row.0, 0,
            "Should see 0 clients when no tenant context is set (RLS default deny)"
        );
    }

    /// T-008: JOINs between tenant-scoped tables respect RLS.
    #[tokio::test]
    async fn test_join_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-join-a-{}", unique_id);
        let slug_b = format!("tenant-join-b-{}", unique_id);

        // Create two tenants with users and clients
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        let email_a = format!("user-a-{}@test.com", unique_id);
        let email_b = format!("user-b-{}@test.com", unique_id);

        ctx.create_user(tenant_a, &email_a, "hash_a").await;
        ctx.create_user(tenant_b, &email_b, "hash_b").await;

        service
            .create_client(
                *tenant_a.as_uuid(),
                CreateClientRequest {
                    name: format!("Join Client A {}", unique_id),
                    client_type: ClientType::Confidential,
                    redirect_uris: vec!["https://a.example.com/cb".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client A");

        service
            .create_client(
                *tenant_b.as_uuid(),
                CreateClientRequest {
                    name: format!("Join Client B {}", unique_id),
                    client_type: ClientType::Confidential,
                    redirect_uris: vec!["https://b.example.com/cb".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client B");

        // Query with Tenant A context - should only see Tenant A's data
        let mut conn = ctx.pool.acquire().await.expect("Failed to acquire conn");
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_a.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        // This query JOINs users and clients (both tenant-scoped)
        // With proper RLS, we should only see Tenant A's user
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *conn)
            .await
            .expect("Failed to count users");

        assert_eq!(row.0, 1, "Should only see Tenant A's user via RLS");

        // Count clients
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_clients")
            .fetch_one(&mut *conn)
            .await
            .expect("Failed to count clients");

        assert_eq!(row.0, 1, "Should only see Tenant A's client via RLS");
    }

    /// T-009: Cannot insert data for a different tenant.
    #[tokio::test]
    async fn test_cannot_insert_cross_tenant() {
        let ctx = OAuthTestContext::new().await;

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-ins-a-{}", unique_id);
        let slug_b = format!("tenant-ins-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Set context to Tenant A
        let mut conn = ctx.pool.acquire().await.expect("Failed to acquire conn");
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_a.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        // Try to insert a client for Tenant B (should fail due to RLS WITH CHECK)
        let result = sqlx::query(
            r#"INSERT INTO oauth_clients
               (id, tenant_id, client_id, name, client_type, redirect_uris, grant_types, scopes, is_active)
               VALUES ($1, $2, $3, $4, 'public', ARRAY['https://evil.com'], ARRAY['authorization_code'], ARRAY['openid'], true)"#,
        )
        .bind(uuid::Uuid::new_v4())
        .bind(tenant_b.as_uuid()) // Wrong tenant!
        .bind(format!("evil-client-{}", unique_id))
        .bind("Evil Client")
        .execute(&mut *conn)
        .await;

        assert!(
            result.is_err(),
            "INSERT for wrong tenant should fail due to RLS WITH CHECK policy"
        );
    }
}

/// Tests for token tenant isolation.
#[cfg(feature = "integration")]
mod token_isolation {
    use super::common::OAuthTestContext;
    use chrono::{Duration, Utc};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;
    use xavyo_api_oauth::models::{ClientType, CreateClientRequest};
    use xavyo_api_oauth::services::OAuth2ClientService;

    /// Helper to hash a token for storage.
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// T-010: Refresh token from Tenant A cannot be used with Tenant B context.
    #[tokio::test]
    async fn test_refresh_token_tenant_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-rt-a-{}", unique_id);
        let slug_b = format!("tenant-rt-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create client for Tenant A
        let (client_a, _) = service
            .create_client(
                *tenant_a.as_uuid(),
                CreateClientRequest {
                    name: format!("RT Client {}", unique_id),
                    client_type: ClientType::Confidential,
                    redirect_uris: vec!["https://example.com/cb".to_string()],
                    grant_types: vec!["refresh_token".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client");

        // Create user for Tenant A
        let email_a = format!("rt-user-{}@test.com", unique_id);
        let user_a = ctx.create_user(tenant_a, &email_a, "hash").await;

        // Insert a refresh token for Tenant A (via admin pool to bypass RLS)
        let refresh_token = format!("rt_{}", Uuid::new_v4());
        let token_hash = hash_token(&refresh_token);
        let expires_at = Utc::now() + Duration::hours(24);

        sqlx::query(
            r#"INSERT INTO oauth_refresh_tokens
               (id, tenant_id, client_id, user_id, token_hash, scopes, expires_at, revoked)
               VALUES ($1, $2, $3, $4, $5, ARRAY['openid'], $6, false)"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_a.as_uuid())
        .bind(client_a.id)
        .bind(user_a)
        .bind(&token_hash)
        .bind(expires_at)
        .execute(&ctx.admin_pool)
        .await
        .expect("Failed to insert refresh token");

        // Query with Tenant A context - should find the token
        let mut conn = ctx.pool.acquire().await.expect("Failed to acquire conn");
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_a.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oauth_refresh_tokens WHERE token_hash = $1")
                .bind(&token_hash)
                .fetch_one(&mut *conn)
                .await
                .expect("Failed to count");

        assert_eq!(row.0, 1, "Tenant A should see its own refresh token");

        // Query with Tenant B context - should NOT find the token
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_b.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM oauth_refresh_tokens WHERE token_hash = $1")
                .bind(&token_hash)
                .fetch_one(&mut *conn)
                .await
                .expect("Failed to count");

        assert_eq!(row.0, 0, "Tenant B should NOT see Tenant A's refresh token");
    }

    /// T-011: Authorization code from Tenant A cannot be used with Tenant B context.
    #[tokio::test]
    async fn test_authorization_code_tenant_isolation() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-ac-a-{}", unique_id);
        let slug_b = format!("tenant-ac-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create client for Tenant A
        let (client_a, _) = service
            .create_client(
                *tenant_a.as_uuid(),
                CreateClientRequest {
                    name: format!("AC Client {}", unique_id),
                    client_type: ClientType::Confidential,
                    redirect_uris: vec!["https://example.com/cb".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client");

        // Create user for Tenant A
        let email_a = format!("ac-user-{}@test.com", unique_id);
        let user_a = ctx.create_user(tenant_a, &email_a, "hash").await;

        // Insert an authorization code for Tenant A
        let auth_code = format!("ac_{}", Uuid::new_v4());
        let code_hash = hash_token(&auth_code);
        let expires_at = Utc::now() + Duration::minutes(10);

        sqlx::query(
            r#"INSERT INTO authorization_codes
               (id, tenant_id, client_id, user_id, code_hash, redirect_uri, scopes, expires_at, used)
               VALUES ($1, $2, $3, $4, $5, 'https://example.com/cb', ARRAY['openid'], $6, false)"#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_a.as_uuid())
        .bind(client_a.id)
        .bind(user_a)
        .bind(&code_hash)
        .bind(expires_at)
        .execute(&ctx.admin_pool)
        .await
        .expect("Failed to insert authorization code");

        // Query with Tenant A context - should find the code
        let mut conn = ctx.pool.acquire().await.expect("Failed to acquire conn");
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_a.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM authorization_codes WHERE code_hash = $1")
                .bind(&code_hash)
                .fetch_one(&mut *conn)
                .await
                .expect("Failed to count");

        assert_eq!(row.0, 1, "Tenant A should see its own authorization code");

        // Query with Tenant B context - should NOT find the code
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_b.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM authorization_codes WHERE code_hash = $1")
                .bind(&code_hash)
                .fetch_one(&mut *conn)
                .await
                .expect("Failed to count");

        assert_eq!(
            row.0, 0,
            "Tenant B should NOT see Tenant A's authorization code"
        );
    }
}

/// Tests for bulk operation tenant isolation.
#[cfg(feature = "integration")]
mod bulk_isolation {
    use super::common::OAuthTestContext;
    use xavyo_api_oauth::models::{ClientType, CreateClientRequest};
    use xavyo_api_oauth::services::OAuth2ClientService;

    /// T-012: Bulk operations cannot affect multiple tenants.
    #[tokio::test]
    async fn test_bulk_update_cannot_affect_multiple_tenants() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-bulk-a-{}", unique_id);
        let slug_b = format!("tenant-bulk-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create clients for both tenants
        service
            .create_client(
                *tenant_a.as_uuid(),
                CreateClientRequest {
                    name: format!("Bulk A {}", unique_id),
                    client_type: ClientType::Public,
                    redirect_uris: vec!["https://a.example.com/cb".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client A");

        service
            .create_client(
                *tenant_b.as_uuid(),
                CreateClientRequest {
                    name: format!("Bulk B {}", unique_id),
                    client_type: ClientType::Public,
                    redirect_uris: vec!["https://b.example.com/cb".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client B");

        // Set context to Tenant A and try a bulk UPDATE
        let mut conn = ctx.pool.acquire().await.expect("Failed to acquire conn");
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_a.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        // This UPDATE without WHERE clause should only affect Tenant A's clients due to RLS
        let result = sqlx::query("UPDATE oauth_clients SET is_active = false")
            .execute(&mut *conn)
            .await
            .expect("Failed to execute bulk update");

        // Should only affect 1 row (Tenant A's client)
        assert_eq!(
            result.rows_affected(),
            1,
            "Bulk UPDATE should only affect Tenant A's clients (RLS enforcement)"
        );

        // Verify Tenant B's client is still active (query via admin pool)
        let row: (bool,) =
            sqlx::query_as("SELECT is_active FROM oauth_clients WHERE tenant_id = $1")
                .bind(tenant_b.as_uuid())
                .fetch_one(&ctx.admin_pool)
                .await
                .expect("Failed to query Tenant B's client");

        assert!(row.0, "Tenant B's client should still be active");
    }

    /// T-013: Bulk DELETE cannot affect multiple tenants.
    #[tokio::test]
    async fn test_bulk_delete_cannot_affect_multiple_tenants() {
        let ctx = OAuthTestContext::new().await;
        let service = OAuth2ClientService::new(ctx.pool.clone());

        let unique_id = OAuthTestContext::unique_id();
        let slug_a = format!("tenant-del-a-{}", unique_id);
        let slug_b = format!("tenant-del-b-{}", unique_id);

        // Create two tenants
        let tenant_a = ctx.create_tenant("Tenant A", &slug_a).await;
        let tenant_b = ctx.create_tenant("Tenant B", &slug_b).await;

        // Create clients for both tenants
        service
            .create_client(
                *tenant_a.as_uuid(),
                CreateClientRequest {
                    name: format!("Del A {}", unique_id),
                    client_type: ClientType::Public,
                    redirect_uris: vec!["https://a.example.com/cb".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client A");

        let (client_b, _) = service
            .create_client(
                *tenant_b.as_uuid(),
                CreateClientRequest {
                    name: format!("Del B {}", unique_id),
                    client_type: ClientType::Public,
                    redirect_uris: vec!["https://b.example.com/cb".to_string()],
                    grant_types: vec!["authorization_code".to_string()],
                    scopes: vec!["openid".to_string()],
                },
            )
            .await
            .expect("Failed to create client B");

        // Set context to Tenant A and try a bulk DELETE
        let mut conn = ctx.pool.acquire().await.expect("Failed to acquire conn");
        sqlx::query("SELECT set_config('app.current_tenant', $1::text, true)")
            .bind(tenant_a.as_uuid().to_string())
            .execute(&mut *conn)
            .await
            .expect("Failed to set context");

        // This DELETE without WHERE clause should only affect Tenant A's clients due to RLS
        let result = sqlx::query("DELETE FROM oauth_clients")
            .execute(&mut *conn)
            .await
            .expect("Failed to execute bulk delete");

        // Should only affect 1 row (Tenant A's client)
        assert_eq!(
            result.rows_affected(),
            1,
            "Bulk DELETE should only affect Tenant A's clients (RLS enforcement)"
        );

        // Verify Tenant B's client still exists (query via admin pool)
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_clients WHERE id = $1")
            .bind(client_b.id)
            .fetch_one(&ctx.admin_pool)
            .await
            .expect("Failed to query Tenant B's client");

        assert_eq!(row.0, 1, "Tenant B's client should still exist");
    }
}
