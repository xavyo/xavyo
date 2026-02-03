//! Integration test helpers for xavyo-api-import.
//!
//! Provides utilities for setting up test databases, creating test data,
//! and generating CSV test files for import testing.

use std::sync::Once;
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::DbPool;

static INIT: Once = Once::new();

/// Initialize logging for tests (once).
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
pub fn get_app_database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://xavyo_app:xavyo_app_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Get the database URL for the superuser (RLS bypassed, for setup operations).
pub fn get_superuser_database_url() -> String {
    std::env::var("DATABASE_URL_SUPERUSER").unwrap_or_else(|_| {
        "postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test".to_string()
    })
}

/// Test context for import integration tests.
///
/// Extends the xavyo-db TestContext pattern with import-specific helpers.
pub struct ImportTestContext {
    /// App user pool - RLS is enforced
    pub pool: DbPool,
    /// Admin/superuser pool - bypasses RLS, used for test setup
    pub admin_pool: DbPool,
}

impl ImportTestContext {
    /// Create a new test context with both app and admin database connections.
    pub async fn new() -> Self {
        init_test_logging();

        let pool = DbPool::connect(&get_app_database_url()).await.expect(
            "Failed to connect as app user. Is PostgreSQL running? Try: ./scripts/dev-env.sh start",
        );

        let admin_pool = DbPool::connect(&get_superuser_database_url())
            .await
            .expect("Failed to connect as superuser");

        Self { pool, admin_pool }
    }

    /// Create a test tenant with unique slug and return its ID.
    pub async fn create_tenant(&self, name: &str, slug: &str) -> TenantId {
        let id = TenantId::new();
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(id.as_uuid())
            .bind(name)
            .bind(slug)
            .execute(self.admin_pool.inner())
            .await
            .expect("Failed to create test tenant");
        id
    }

    /// Create a unique test tenant with generated slug.
    pub async fn create_unique_tenant(&self, prefix: &str) -> TenantId {
        let unique_id = &Uuid::new_v4().to_string()[..8];
        let slug = format!("{}-{}", prefix, unique_id);
        let name = format!("Test Tenant {}", unique_id);
        self.create_tenant(&name, &slug).await
    }

    /// Create a test user for a tenant.
    pub async fn create_user(&self, tenant_id: TenantId, email: &str, password_hash: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, password_hash) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(tenant_id.as_uuid())
        .bind(email)
        .bind(password_hash)
        .execute(self.admin_pool.inner())
        .await
        .expect("Failed to create test user");
        id
    }

    /// Create an import job directly in the database for testing.
    pub async fn create_import_job(
        &self,
        tenant_id: TenantId,
        file_name: &str,
        total_rows: i32,
        status: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let file_hash = format!("test_hash_{}", Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO user_import_jobs
                (id, tenant_id, status, file_name, file_hash, file_size_bytes, total_rows, send_invitations)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(id)
        .bind(tenant_id.as_uuid())
        .bind(status)
        .bind(file_name)
        .bind(&file_hash)
        .bind(1000i64) // file_size_bytes
        .bind(total_rows)
        .bind(false) // send_invitations
        .execute(self.admin_pool.inner())
        .await
        .expect("Failed to create test import job");
        id
    }

    /// Create an import error record for testing.
    pub async fn create_import_error(
        &self,
        job_id: Uuid,
        line_number: i32,
        email: Option<&str>,
        error_type: &str,
        error_message: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO user_import_errors
                (id, job_id, line_number, email, error_type, error_message)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(id)
        .bind(job_id)
        .bind(line_number)
        .bind(email)
        .bind(error_type)
        .bind(error_message)
        .execute(self.admin_pool.inner())
        .await
        .expect("Failed to create test import error");
        id
    }

    /// Create a user invitation for testing.
    pub async fn create_invitation(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        email: &str,
        token_hash: &str,
        status: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Uuid {
        let id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO user_invitations
                (id, tenant_id, user_id, email, token_hash, status, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(tenant_id.as_uuid())
        .bind(user_id)
        .bind(email)
        .bind(token_hash)
        .bind(status)
        .bind(expires_at)
        .execute(self.admin_pool.inner())
        .await
        .expect("Failed to create test invitation");
        id
    }

    /// Get the well-known test tenant ID (from seed data).
    #[allow(dead_code)]
    pub fn seed_tenant_id() -> TenantId {
        TenantId::from_uuid(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001")
                .expect("Invalid seed tenant UUID"),
        )
    }
}

// ---------------------------------------------------------------------------
// CSV Test Data Generators
// ---------------------------------------------------------------------------

/// Generate a valid CSV string with the specified number of rows.
pub fn generate_valid_csv(row_count: usize, prefix: &str) -> String {
    let mut csv = String::from("email,first_name,last_name,department\n");
    for i in 0..row_count {
        csv.push_str(&format!(
            "{}-{}@test.xavyo.com,Test,User{},{}\n",
            prefix, i, i, "Engineering"
        ));
    }
    csv
}

/// Generate a CSV with invalid email formats.
pub fn generate_invalid_email_csv(prefix: &str) -> String {
    format!(
        r#"email,first_name,last_name
{}-valid@test.xavyo.com,Valid,User
invalid-email,Invalid,User
@nodomain,No,Domain
missing-at.com,Missing,At
{}-valid2@test.xavyo.com,Valid,User2
"#,
        prefix, prefix
    )
}

/// Generate a CSV with duplicate emails.
pub fn generate_duplicate_email_csv(prefix: &str) -> String {
    format!(
        r#"email,first_name,last_name
{}-dup@test.xavyo.com,First,Occurrence
{}-unique@test.xavyo.com,Unique,User
{}-dup@test.xavyo.com,Second,Occurrence
{}-dup@test.xavyo.com,Third,Occurrence
"#,
        prefix, prefix, prefix, prefix
    )
}

/// Generate a CSV missing the email column.
pub fn generate_missing_email_column_csv() -> String {
    String::from(
        r#"first_name,last_name,department
John,Doe,Engineering
Jane,Smith,Sales
"#,
    )
}

/// Generate a CSV with empty email fields.
pub fn generate_empty_email_csv(prefix: &str) -> String {
    format!(
        r#"email,first_name,last_name
{}-valid@test.xavyo.com,Valid,User
,Empty,Email
{}-valid2@test.xavyo.com,Valid,User2
,Another,Empty
"#,
        prefix, prefix
    )
}

/// Generate a semicolon-delimited CSV (European format).
pub fn generate_semicolon_csv(prefix: &str) -> String {
    format!(
        r#"email;first_name;last_name
{}-euro@test.xavyo.com;Euro;User
"#,
        prefix
    )
}

/// Generate a header-only CSV (no data rows).
pub fn generate_empty_csv() -> String {
    String::from("email,first_name,last_name,department\n")
}

/// Generate a CSV with very long field values.
pub fn generate_long_field_csv(prefix: &str) -> String {
    let long_name = "A".repeat(500); // Exceeds typical VARCHAR limits
    format!(
        r#"email,first_name,last_name
{}-long@test.xavyo.com,{},{}
"#,
        prefix, long_name, long_name
    )
}

/// Generate a large CSV with specified row count for performance testing.
pub fn generate_large_csv(row_count: usize, error_rate: f64) -> String {
    let unique_id = &Uuid::new_v4().to_string()[..8];
    let mut csv = String::from("email,first_name,last_name,department\n");

    let error_interval = if error_rate > 0.0 {
        (1.0 / error_rate) as usize
    } else {
        usize::MAX
    };

    for i in 0..row_count {
        if error_rate > 0.0 && i % error_interval == 0 && i > 0 {
            // Insert an invalid email
            csv.push_str(&format!("invalid-email-{},Test,User{},Engineering\n", i, i));
        } else {
            csv.push_str(&format!(
                "perf-{}-{}@test.xavyo.com,Test,User{},Engineering\n",
                unique_id, i, i
            ));
        }
    }
    csv
}

/// Generate a CSV with mixed valid and invalid rows.
pub fn generate_mixed_csv(prefix: &str) -> String {
    format!(
        r#"email,first_name,last_name
{}-valid1@test.xavyo.com,Valid,User1
invalid-email,Invalid,User
{}-valid2@test.xavyo.com,Valid,User2
,Empty,Email
{}-valid3@test.xavyo.com,Valid,User3
{}-dup@test.xavyo.com,First,Dup
{}-dup@test.xavyo.com,Second,Dup
{}-valid4@test.xavyo.com,Valid,User4
"#,
        prefix, prefix, prefix, prefix, prefix, prefix
    )
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Generate a unique test prefix for isolating test data.
pub fn unique_test_prefix(test_name: &str) -> String {
    let unique_id = &Uuid::new_v4().to_string()[..8];
    format!("{}-{}", test_name, unique_id)
}
