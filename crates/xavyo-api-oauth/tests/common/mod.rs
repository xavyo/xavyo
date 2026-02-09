//! Common test utilities for xavyo-api-oauth integration tests.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Once;
use std::time::Duration;
use uuid::Uuid;
use xavyo_api_oauth::router::OAuthState;
use xavyo_core::TenantId;

#[allow(dead_code)]
static INIT: Once = Once::new();

/// RSA key pair for testing (2048-bit).
/// Generated with openssl - These are TEST KEYS, DO NOT use in production.
#[allow(dead_code)]
const TEST_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWvwXoegwG34YX
q+6MmsAfjZz2OZfBwbGVZSW0tiskb9UXZ2Rdz99ayewaKcLw1xwDcmI3BZWKcgfa
T2lnJbMeMv0SuewOAkZQ8ucZEScGHNcmBflGPUR/7ktUp55BJXFzkkqURqS3ORMp
Ds+4yx/GKez5HyOuK+gp0IxpoWhMMAGCA/7A3n3OLRbIkClK92u1sdCxtp5c9vEM
1oBK97p1qsPzRCUS3YLAnXAgbY8JOePbTdMrsqG2Y0/oXkjdGmcXH2KcMuRqnFql
qxegPR66n4k9LsBYk+dmKkDnAikOs0dpTWyaRI1POeLEOsjzfIL/xtZDOEK9QaaC
6S5ekP/dAgMBAAECggEACXmXvjk/nMX7aGz82TcX2NPemAZeMMZDKnP5Vv61PvzN
fMNZpmDctdjnv2w9DcTDhL7xh+pQsCtDLZhctGhE9iK3z+/CM842S7u8xVFT7dkt
t7zb4muS7OSWNQu1EXywQRaim+fFziNm/idpbIDN7jdv5uerZzToyooKbVBBHTq1
dbd+egtlLh6mGdAcpaw4CpURwH5+b5DwPwl2c8hYJKmGTEQj+FK8K9xSDVX0sov8
yseSTPo3Q1gp38lDJBZkNtxbzXORtjvTWldxI9FQtCLasedzX/HXqxh1c3qVbaVw
EZTqTSSmZX4VWD7YgweNSufxhyM5Nbd/vzaEhiFX6QKBgQDTycPQ7G0cImvnlCNX
RGMDYShHxXEe0iCoUDZoONNeVNqrs/MPVYlNiX3+Gy4VTmQpqGOAFr5afXVa3SSf
MDr+bhtJSK0MGNR/SmUsFvrCeDcDh2ZrbYFD69kEdALgM7VLs6YuBH1fJgmhhsjm
4X09bx1VpHEAh5+kSMwA6x2b1QKBgQC2NxiYQS1s005yZ2NcaO+gWk9gFpgQrvfL
C6nl/vt0wOy/P/0YApxAnQd+OQQfcfygQFj8/UZsAoI2HXj22x+ub5ZiJL/dZY6F
SarJQulNVODBsnrNHhUKLhH/mGxX3YB6pOPcX46/h6tJEM+xomBzMwXLkJPfUkkI
Gi9XRFH/6QKBgDqt1nFWcEyxRNBe/QO60OwoyS5JiDQP6Dh6MPjjdbzXKdcU/q0q
9+XhyGTVRwlkNOBN5XOh2Y/c3t0UFId+p3nDLBA78KY/YvD5vdpfa47iG+wAYeI1
7vDQscpIElvoN70Hw21QlSP9uAFnBNbjdv3EgY4vB5gr+5FbEhrXCdcZAoGAJ5Hf
bXD6BF/+8SkykqbXIuN5yUweycC1XwqxYpj00m3y+7VRqR0oAYAYWHjZRFrkmYhf
ytDVsi75R/cuha0gPClPZxDD+bhMMvXEeOBm+bws8uNnd5PIzeUjU3YuUQZxGDEm
qny16zHzKHLWJ6UzfNDfuU00T5L2+SN2lGTpycECgYEAmoV1LnfOnv7ytid8kHE8
tOmUhF0TRxS3K/I1d0EGkM0PcR4BVSxHYz0LU0ChL4SOYuo7yKzESChwdDRvm1MN
6vj1477kZXDY2XxVkiXZSD3kPRZ3RFTRIf4nObHi8sKMbGKkJUyDeN+n2SIvYST2
xxU7T7aU32bKZLygCDtwsN8=
-----END PRIVATE KEY-----";

/// Test RSA public key (matches the private key above).
#[allow(dead_code)]
const TEST_PUBLIC_KEY: &str = r"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlr8F6HoMBt+GF6vujJrA
H42c9jmXwcGxlWUltLYrJG/VF2dkXc/fWsnsGinC8NccA3JiNwWVinIH2k9pZyWz
HjL9ErnsDgJGUPLnGREnBhzXJgX5Rj1Ef+5LVKeeQSVxc5JKlEaktzkTKQ7PuMsf
xins+R8jrivoKdCMaaFoTDABggP+wN59zi0WyJApSvdrtbHQsbaeXPbxDNaASve6
darD80QlEt2CwJ1wIG2PCTnj203TK7KhtmNP6F5I3RpnFx9inDLkapxapasXoD0e
up+JPS7AWJPnZipA5wIpDrNHaU1smkSNTznixDrI83yC/8bWQzhCvUGmgukuXpD/
3QIDAQAB
-----END PUBLIC KEY-----";

/// Test CSRF secret (32 bytes) - DO NOT use in production.
/// This is a secure random value for testing only.
#[allow(dead_code)]
const TEST_CSRF_SECRET: [u8; 32] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0xFE, 0xED, 0xFA, 0xCE, 0x0D, 0xD0, 0x0D, 0xAD, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
];

/// Initialize logging for tests (once).
#[allow(dead_code)]
pub fn init_test_logging() {
    INIT.call_once(|| {
        if std::env::var("RUST_LOG").is_ok() {
            tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init()
                .ok();
        }
    });
}

/// Get the database URL for the app user (non-superuser, RLS enforced).
#[allow(dead_code)]
pub fn get_app_database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://xavyo_app:xavyo_app_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Get the database URL for the superuser (RLS bypassed, for setup operations).
#[allow(dead_code)]
pub fn get_superuser_database_url() -> String {
    std::env::var("DATABASE_URL_SUPERUSER").unwrap_or_else(|_| {
        "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Test context for OAuth integration tests.
///
/// Provides database pools and helpers for tenant isolation testing.
#[allow(dead_code)]
pub struct OAuthTestContext {
    /// App user pool - RLS is enforced
    pub pool: PgPool,
    /// Admin/superuser pool - bypasses RLS, used for test setup
    pub admin_pool: PgPool,
}

impl OAuthTestContext {
    /// Create a new test context with both app and admin database connections.
    #[allow(dead_code)]
    pub async fn new() -> Self {
        init_test_logging();

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&get_app_database_url())
            .await
            .expect("Failed to connect as app user. Is PostgreSQL running?");

        let admin_pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&get_superuser_database_url())
            .await
            .expect("Failed to connect as superuser");

        Self { pool, admin_pool }
    }

    /// Create a test tenant and return its ID.
    #[allow(dead_code)]
    pub async fn create_tenant(&self, name: &str, slug: &str) -> TenantId {
        let id = TenantId::new();
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(id.as_uuid())
            .bind(name)
            .bind(slug)
            .execute(&self.admin_pool)
            .await
            .expect("Failed to create test tenant");
        id
    }

    /// Create a test user for a tenant.
    #[allow(dead_code)]
    pub async fn create_user(&self, tenant_id: TenantId, email: &str, password_hash: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified)
             VALUES ($1, $2, $3, $4, true, true)",
        )
        .bind(id)
        .bind(tenant_id.as_uuid())
        .bind(email)
        .bind(password_hash)
        .execute(&self.admin_pool)
        .await
        .expect("Failed to create test user");
        id
    }

    /// Create OAuth state with the test database pool.
    #[allow(dead_code)]
    pub fn create_oauth_state(&self) -> OAuthState {
        OAuthState::new(
            self.pool.clone(),
            "https://idp.test.xavyo.com".to_string(),
            TEST_PRIVATE_KEY.as_bytes().to_vec(),
            TEST_PUBLIC_KEY.as_bytes().to_vec(),
            "test-key-1".to_string(),
            TEST_CSRF_SECRET.to_vec(),
        )
    }

    /// Get a unique identifier for test isolation.
    #[allow(dead_code)]
    pub fn unique_id() -> String {
        Uuid::new_v4().to_string()[..8].to_string()
    }
}

/// Create a test OAuth state without a database connection.
///
/// This uses mock services that don't require database connectivity,
/// suitable for testing the discovery endpoints which don't need DB access.
#[allow(dead_code)]
pub fn create_test_state() -> OAuthState {
    create_test_state_with_keys(
        TEST_PRIVATE_KEY.as_bytes().to_vec(),
        TEST_PUBLIC_KEY.as_bytes().to_vec(),
        "test-key-1".to_string(),
    )
}

/// Create a test OAuth state with custom keys.
#[allow(dead_code)]
pub fn create_test_state_with_keys(
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    key_id: String,
) -> OAuthState {
    let pool = create_mock_pool();

    OAuthState::new(
        pool,
        "https://idp.test.xavyo.com".to_string(),
        private_key,
        public_key,
        key_id,
        TEST_CSRF_SECRET.to_vec(),
    )
}

/// Create a mock database pool for testing.
///
/// This creates a pool that will fail on actual queries but works
/// for endpoints that don't need database access.
#[allow(dead_code)]
fn create_mock_pool() -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://invalid:invalid@localhost/invalid")
        .expect("Failed to create mock pool")
}
