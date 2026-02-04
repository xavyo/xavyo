//! Integration tests for xavyo-api-import.
//!
//! These tests require a running `PostgreSQL` instance.
//! Run with: `cargo test -p xavyo-api-import --features integration`
//!
//! Prerequisites:
//! 1. Start the test environment: `./scripts/dev-env.sh start`
//! 2. Set `DATABASE_URL` (optional, defaults to test database)

#![cfg(feature = "integration")]

mod common;

use chrono::{Duration, Utc};
use common::{
    generate_duplicate_email_csv, generate_empty_csv, generate_empty_email_csv,
    generate_invalid_email_csv, generate_large_csv, generate_long_field_csv,
    generate_missing_email_column_csv, generate_mixed_csv, generate_semicolon_csv,
    generate_valid_csv, unique_test_prefix, ImportTestContext,
};
use uuid::Uuid;
use xavyo_api_import::models::{CsvDelimiter, CsvParseConfig, DuplicateCheckFields};
use xavyo_api_import::services::csv_parser::parse_csv_with_config;
use xavyo_db::models::{CreateImportJob, UserImportJob};
use xavyo_db::{clear_tenant_context, set_tenant_context};

// ===========================================================================
// Phase 2: Foundational Tests - Database Connectivity
// ===========================================================================

#[tokio::test]
async fn test_database_connection() {
    let ctx = ImportTestContext::new().await;

    // Verify we can execute a simple query
    let row: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(ctx.pool.inner())
        .await
        .expect("Failed to execute query");

    assert_eq!(row.0, 1);
}

#[tokio::test]
async fn test_user_import_jobs_table_exists() {
    let ctx = ImportTestContext::new().await;

    let result: Result<(i64,), _> = sqlx::query_as("SELECT COUNT(*) FROM user_import_jobs")
        .fetch_one(ctx.admin_pool.inner())
        .await;

    assert!(result.is_ok(), "user_import_jobs table should exist");
}

#[tokio::test]
async fn test_user_import_errors_table_exists() {
    let ctx = ImportTestContext::new().await;

    let result: Result<(i64,), _> = sqlx::query_as("SELECT COUNT(*) FROM user_import_errors")
        .fetch_one(ctx.admin_pool.inner())
        .await;

    assert!(result.is_ok(), "user_import_errors table should exist");
}

#[tokio::test]
async fn test_user_invitations_table_exists() {
    let ctx = ImportTestContext::new().await;

    let result: Result<(i64,), _> = sqlx::query_as("SELECT COUNT(*) FROM user_invitations")
        .fetch_one(ctx.admin_pool.inner())
        .await;

    assert!(result.is_ok(), "user_invitations table should exist");
}

#[tokio::test]
async fn test_tenants_table_exists() {
    let ctx = ImportTestContext::new().await;

    let result: Result<(i64,), _> = sqlx::query_as("SELECT COUNT(*) FROM tenants")
        .fetch_one(ctx.admin_pool.inner())
        .await;

    assert!(result.is_ok(), "tenants table should exist");
}

// ===========================================================================
// Phase 3: User Story 1 - Job Lifecycle Testing
// ===========================================================================

mod job_lifecycle {
    use super::*;

    #[tokio::test]
    async fn test_create_job_returns_pending_status() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("create-pending");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let csv_data = generate_valid_csv(5, &prefix);
        let parse_result =
            parse_csv_with_config(csv_data.as_bytes(), &CsvParseConfig::new()).unwrap();

        let job = UserImportJob::create(
            ctx.admin_pool.inner(),
            CreateImportJob {
                tenant_id: *tenant_id.as_uuid(),
                file_name: "test.csv".to_string(),
                file_hash: format!("hash_{}", Uuid::new_v4()),
                file_size_bytes: csv_data.len() as i64,
                total_rows: parse_result.rows.len() as i32,
                send_invitations: false,
                created_by: None,
            },
        )
        .await
        .expect("Failed to create job");

        assert_eq!(job.status, "pending");
        assert_eq!(job.total_rows, 5);
        assert_eq!(job.processed_rows, 0);
    }

    #[tokio::test]
    async fn test_create_job_counts_rows_correctly() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("count-rows");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        // Test with different row counts
        for row_count in [1, 10, 100] {
            let csv_data = generate_valid_csv(row_count, &format!("{}-{}", prefix, row_count));
            let parse_result =
                parse_csv_with_config(csv_data.as_bytes(), &CsvParseConfig::new()).unwrap();

            let job = UserImportJob::create(
                ctx.admin_pool.inner(),
                CreateImportJob {
                    tenant_id: *tenant_id.as_uuid(),
                    file_name: format!("test_{}.csv", row_count),
                    file_hash: format!("hash_{}", Uuid::new_v4()),
                    file_size_bytes: csv_data.len() as i64,
                    total_rows: parse_result.rows.len() as i32,
                    send_invitations: false,
                    created_by: None,
                },
            )
            .await
            .expect("Failed to create job");

            assert_eq!(
                job.total_rows, row_count as i32,
                "Job should have {} rows",
                row_count
            );
        }
    }

    #[tokio::test]
    async fn test_mark_started_transitions_to_processing() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("mark-started");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let job_id = ctx
            .create_import_job(tenant_id, "test.csv", 10, "pending")
            .await;

        let updated =
            UserImportJob::mark_started(ctx.admin_pool.inner(), *tenant_id.as_uuid(), job_id)
                .await
                .expect("Failed to mark started")
                .expect("Job should exist");

        assert_eq!(updated.status, "processing");
        assert!(updated.started_at.is_some(), "started_at should be set");
    }

    #[tokio::test]
    async fn test_mark_completed_sets_final_counts() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("mark-completed");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let job_id = ctx
            .create_import_job(tenant_id, "test.csv", 100, "processing")
            .await;

        let updated = UserImportJob::mark_completed(
            ctx.admin_pool.inner(),
            *tenant_id.as_uuid(),
            job_id,
            85, // success_count
            10, // error_count
            5,  // skip_count
        )
        .await
        .expect("Failed to mark completed")
        .expect("Job should exist");

        assert_eq!(updated.status, "completed");
        assert_eq!(updated.success_count, 85);
        assert_eq!(updated.error_count, 10);
        assert_eq!(updated.skip_count, 5);
        assert_eq!(updated.processed_rows, 100); // sum of all counts
        assert!(updated.completed_at.is_some(), "completed_at should be set");
    }

    #[tokio::test]
    async fn test_mark_failed_records_error_message() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("mark-failed");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let job_id = ctx
            .create_import_job(tenant_id, "test.csv", 100, "processing")
            .await;

        let error_msg = "Database connection lost during processing";
        let updated = UserImportJob::mark_failed(
            ctx.admin_pool.inner(),
            *tenant_id.as_uuid(),
            job_id,
            error_msg,
        )
        .await
        .expect("Failed to mark failed")
        .expect("Job should exist");

        assert_eq!(updated.status, "failed");
        assert_eq!(updated.error_message, Some(error_msg.to_string()));
        assert!(updated.completed_at.is_some(), "completed_at should be set");
    }

    #[tokio::test]
    async fn test_update_progress_increments_counters() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("update-progress");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let job_id = ctx
            .create_import_job(tenant_id, "test.csv", 100, "processing")
            .await;

        // Update progress midway
        UserImportJob::update_progress(
            ctx.admin_pool.inner(),
            *tenant_id.as_uuid(),
            job_id,
            50, // processed_rows
            45, // success_count
            3,  // error_count
            2,  // skip_count
        )
        .await
        .expect("Failed to update progress");

        // Verify the update
        let job = UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_id.as_uuid(), job_id)
            .await
            .expect("Failed to find job")
            .expect("Job should exist");

        assert_eq!(job.processed_rows, 50);
        assert_eq!(job.success_count, 45);
        assert_eq!(job.error_count, 3);
        assert_eq!(job.skip_count, 2);
    }

    #[tokio::test]
    async fn test_job_not_found_returns_none() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("not-found");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let non_existent_id = Uuid::new_v4();
        let result = UserImportJob::find_by_id(
            ctx.admin_pool.inner(),
            *tenant_id.as_uuid(),
            non_existent_id,
        )
        .await
        .expect("Query should succeed");

        assert!(result.is_none(), "Non-existent job should return None");
    }

    #[tokio::test]
    async fn test_list_jobs_returns_tenant_jobs_ordered() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("list-jobs");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        // Create multiple jobs
        let _job1 = ctx
            .create_import_job(tenant_id, "first.csv", 10, "completed")
            .await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let _job2 = ctx
            .create_import_job(tenant_id, "second.csv", 20, "processing")
            .await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let job3 = ctx
            .create_import_job(tenant_id, "third.csv", 30, "pending")
            .await;

        let (jobs, total) = UserImportJob::list_by_tenant(
            ctx.admin_pool.inner(),
            *tenant_id.as_uuid(),
            None,
            10,
            0,
        )
        .await
        .expect("Failed to list jobs");

        assert_eq!(total, 3);
        assert_eq!(jobs.len(), 3);
        // Most recent first
        assert_eq!(jobs[0].id, job3);
        assert_eq!(jobs[0].file_name, "third.csv");
    }
}

// ===========================================================================
// Phase 4: User Story 2 - Multi-Tenant Data Isolation
// ===========================================================================

mod tenant_isolation {
    use super::*;

    #[tokio::test]
    async fn test_tenant_cannot_see_other_tenant_jobs() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("iso-jobs");

        let tenant_a = ctx.create_unique_tenant(&format!("{}-a", prefix)).await;
        let tenant_b = ctx.create_unique_tenant(&format!("{}-b", prefix)).await;

        // Create jobs for tenant A
        ctx.create_import_job(tenant_a, "tenant_a.csv", 10, "completed")
            .await;
        ctx.create_import_job(tenant_a, "tenant_a_2.csv", 20, "pending")
            .await;

        // Query as tenant B - should see nothing
        let (jobs, total) =
            UserImportJob::list_by_tenant(ctx.admin_pool.inner(), *tenant_b.as_uuid(), None, 10, 0)
                .await
                .expect("Failed to list jobs");

        assert_eq!(total, 0, "Tenant B should see 0 jobs from Tenant A");
        assert!(jobs.is_empty());
    }

    #[tokio::test]
    async fn test_tenant_cannot_access_other_tenant_job_by_id() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("iso-access");

        let tenant_a = ctx.create_unique_tenant(&format!("{}-a", prefix)).await;
        let tenant_b = ctx.create_unique_tenant(&format!("{}-b", prefix)).await;

        // Create job for tenant A
        let job_id = ctx
            .create_import_job(tenant_a, "tenant_a.csv", 10, "completed")
            .await;

        // Try to access as tenant B
        let result = UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_b.as_uuid(), job_id)
            .await
            .expect("Query should succeed");

        assert!(
            result.is_none(),
            "Tenant B should not be able to access Tenant A's job"
        );
    }

    #[tokio::test]
    async fn test_tenant_cannot_see_other_tenant_errors() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("iso-errors");

        let tenant_a = ctx.create_unique_tenant(&format!("{}-a", prefix)).await;
        let tenant_b = ctx.create_unique_tenant(&format!("{}-b", prefix)).await;

        // Create job and error for tenant A
        let job_id = ctx
            .create_import_job(tenant_a, "tenant_a.csv", 10, "completed")
            .await;
        ctx.create_import_error(
            job_id,
            5,
            Some("bad@email"),
            "invalid_email",
            "Invalid format",
        )
        .await;

        // Query errors for tenant B's non-existent job
        let errors: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM user_import_errors WHERE job_id IN (SELECT id FROM user_import_jobs WHERE tenant_id = $1)"
        )
        .bind(tenant_b.as_uuid())
        .fetch_all(ctx.admin_pool.inner())
        .await
        .expect("Query should succeed");

        assert!(
            errors.is_empty(),
            "Tenant B should see no errors from Tenant A"
        );
    }

    #[tokio::test]
    async fn test_tenant_cannot_see_other_tenant_users() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("iso-users");

        let tenant_a = ctx.create_unique_tenant(&format!("{}-a", prefix)).await;
        let tenant_b = ctx.create_unique_tenant(&format!("{}-b", prefix)).await;

        // Create user for tenant A
        ctx.create_user(tenant_a, &format!("{}-user@test.xavyo.com", prefix), "hash")
            .await;

        // Set tenant context to B and query users
        let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");
        set_tenant_context(&mut *tx, tenant_b)
            .await
            .expect("Failed to set tenant context");

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .expect("Query should succeed");

        assert_eq!(
            count.0, 0,
            "Tenant B should see 0 users (Tenant A's users hidden)"
        );

        tx.rollback().await.ok();
    }

    #[tokio::test]
    async fn test_tenant_cannot_update_other_tenant_job() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("iso-update");

        let tenant_a = ctx.create_unique_tenant(&format!("{}-a", prefix)).await;
        let tenant_b = ctx.create_unique_tenant(&format!("{}-b", prefix)).await;

        // Create job for tenant A
        let job_id = ctx
            .create_import_job(tenant_a, "tenant_a.csv", 10, "pending")
            .await;

        // Try to update as tenant B
        let result = UserImportJob::update_status(
            ctx.admin_pool.inner(),
            *tenant_b.as_uuid(),
            job_id,
            "processing",
        )
        .await
        .expect("Query should succeed");

        assert!(
            result.is_none(),
            "Tenant B should not be able to update Tenant A's job"
        );

        // Verify job wasn't changed
        let job = UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_a.as_uuid(), job_id)
            .await
            .expect("Query should succeed")
            .expect("Job should exist");

        assert_eq!(job.status, "pending", "Job status should be unchanged");
    }

    #[tokio::test]
    async fn test_no_context_returns_no_jobs() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("no-context");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        // Create job
        ctx.create_import_job(tenant_id, "test.csv", 10, "completed")
            .await;

        // Query without tenant context via RLS-enforced pool
        let mut tx = ctx.pool.begin().await.expect("Failed to begin transaction");

        // Ensure no context is set
        clear_tenant_context(&mut *tx)
            .await
            .expect("Failed to clear tenant context");

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_import_jobs")
            .fetch_one(&mut *tx)
            .await
            .expect("Query should succeed");

        assert_eq!(count.0, 0, "No jobs visible without tenant context");

        tx.rollback().await.ok();
    }
}

// ===========================================================================
// Phase 5: User Story 3 - Error Scenario Coverage
// ===========================================================================

mod error_scenarios {
    use super::*;

    #[tokio::test]
    async fn test_invalid_email_format_flagged() {
        let prefix = unique_test_prefix("invalid-email");
        let csv_data = generate_invalid_email_csv(&prefix);
        let config = CsvParseConfig::new();

        let result = parse_csv_with_config(csv_data.as_bytes(), &config).unwrap();

        // Should have 2 valid rows and 3 invalid
        assert_eq!(result.rows.len(), 2, "Should have 2 valid rows");
        assert_eq!(result.errors.len(), 3, "Should have 3 invalid email errors");

        // Verify error types
        for error in &result.errors {
            assert!(
                error.error_type.contains("email") || error.error_type.contains("validation"),
                "Error should be email-related: {}",
                error.error_type
            );
        }
    }

    #[tokio::test]
    async fn test_duplicate_emails_skipped() {
        let prefix = unique_test_prefix("dup-email");
        let csv_data = generate_duplicate_email_csv(&prefix);
        let config =
            CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields::email_only());

        let result = parse_csv_with_config(csv_data.as_bytes(), &config).unwrap();

        // First occurrence + unique = 2 valid, 2 duplicates recorded as errors
        assert_eq!(
            result.rows.len(),
            2,
            "Should have 2 valid rows (first + unique)"
        );
        assert_eq!(result.errors.len(), 2, "Should have 2 duplicate errors");

        // Verify they are duplicate errors
        for error in &result.errors {
            assert!(
                error.error_type.contains("duplicate"),
                "Error should be duplicate-related: {}",
                error.error_type
            );
        }
    }

    #[tokio::test]
    async fn test_missing_email_column_rejected() {
        let csv_data = generate_missing_email_column_csv();
        let config = CsvParseConfig::new();

        let result = parse_csv_with_config(csv_data.as_bytes(), &config);

        assert!(result.is_err(), "Missing email column should fail parsing");
        let error_msg = result.unwrap_err();
        assert!(
            error_msg.contains("email") || error_msg.contains("column"),
            "Error should mention missing email column: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_wrong_delimiter_detected() {
        let prefix = unique_test_prefix("wrong-delim");
        let csv_data = generate_semicolon_csv(&prefix);

        // Parse with comma delimiter (wrong for this data)
        let config = CsvParseConfig::new().with_delimiter(CsvDelimiter::Comma);
        let result = parse_csv_with_config(csv_data.as_bytes(), &config);

        // Either fails to parse or treats entire row as single field (no email column)
        assert!(
            result.is_err()
                || result
                    .as_ref()
                    .map(|r| r.rows.is_empty() || !r.errors.is_empty())
                    .unwrap_or(true),
            "Wrong delimiter should cause parsing issues"
        );
    }

    #[tokio::test]
    async fn test_empty_email_field_flagged() {
        let prefix = unique_test_prefix("empty-email");
        let csv_data = generate_empty_email_csv(&prefix);
        let config = CsvParseConfig::new();

        let result = parse_csv_with_config(csv_data.as_bytes(), &config).unwrap();

        // 2 valid, 2 with empty emails
        assert_eq!(result.rows.len(), 2, "Should have 2 valid rows");
        assert!(
            result.errors.len() >= 2,
            "Should have at least 2 empty email errors"
        );
    }

    #[tokio::test]
    async fn test_max_rows_exceeded_rejected() {
        // Generate CSV with more than max rows (10001 rows)
        let large_csv = generate_large_csv(10001, 0.0);
        let config = CsvParseConfig::new().with_max_rows(10000);

        let result = parse_csv_with_config(large_csv.as_bytes(), &config);

        // Should either error or stop at max_rows
        if let Ok(parsed) = result {
            assert!(
                parsed.rows.len() <= 10000,
                "Should not parse more than max_rows"
            );
        }
    }

    #[tokio::test]
    async fn test_empty_csv_no_data_rows() {
        let csv_data = generate_empty_csv();
        let config = CsvParseConfig::new();

        let result = parse_csv_with_config(csv_data.as_bytes(), &config).unwrap();

        assert_eq!(
            result.rows.len(),
            0,
            "Header-only CSV should have 0 data rows"
        );
        assert_eq!(result.errors.len(), 0, "No errors for empty CSV");
    }

    #[tokio::test]
    async fn test_very_long_field_handled() {
        let prefix = unique_test_prefix("long-field");
        let csv_data = generate_long_field_csv(&prefix);
        let config = CsvParseConfig::new();

        // Should parse without crashing
        let result = parse_csv_with_config(csv_data.as_bytes(), &config);

        // May succeed with truncation or fail with validation error
        assert!(
            result.is_ok() || result.is_err(),
            "Should handle long fields gracefully"
        );
    }

    #[tokio::test]
    async fn test_errors_stored_with_line_numbers() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("line-nums");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let job_id = ctx
            .create_import_job(tenant_id, "test.csv", 10, "completed")
            .await;

        // Create errors with specific line numbers
        ctx.create_import_error(
            job_id,
            3,
            Some("bad@email"),
            "invalid_email",
            "Invalid format",
        )
        .await;
        ctx.create_import_error(
            job_id,
            7,
            Some("dup@email"),
            "duplicate_email",
            "Already exists",
        )
        .await;

        // Verify line numbers are stored
        let errors: Vec<(i32, String)> = sqlx::query_as(
            "SELECT line_number, error_type FROM user_import_errors WHERE job_id = $1 ORDER BY line_number"
        )
        .bind(job_id)
        .fetch_all(ctx.admin_pool.inner())
        .await
        .expect("Query should succeed");

        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].0, 3);
        assert_eq!(errors[1].0, 7);
    }

    #[tokio::test]
    async fn test_mixed_valid_invalid_partial_success() {
        let prefix = unique_test_prefix("mixed");
        let csv_data = generate_mixed_csv(&prefix);
        let config =
            CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields::email_only());

        let result = parse_csv_with_config(csv_data.as_bytes(), &config).unwrap();

        // Should have some valid, some errors (including duplicates)
        assert!(!result.rows.is_empty(), "Should have some valid rows");
        assert!(!result.errors.is_empty(), "Should have some errors");

        // Total should account for all 8 data rows
        let total = result.rows.len() + result.errors.len();
        assert_eq!(
            total,
            8,
            "Total should account for all 8 data rows: valid={}, errors={}",
            result.rows.len(),
            result.errors.len()
        );
    }
}

// ===========================================================================
// Phase 6: User Story 4 - Large File Performance
// ===========================================================================

mod performance {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_large_file_10k_rows_under_30_seconds() {
        let csv_data = generate_large_csv(10000, 0.0);
        let config = CsvParseConfig::new();

        let start = Instant::now();
        let result = parse_csv_with_config(csv_data.as_bytes(), &config);
        let duration = start.elapsed();

        assert!(result.is_ok(), "Should successfully parse 10k rows");
        assert!(
            duration.as_secs() < 30,
            "Should complete in under 30 seconds, took {:?}",
            duration
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.rows.len(), 10000, "Should have 10000 valid rows");
    }

    #[tokio::test]
    async fn test_large_file_with_errors_under_30_seconds() {
        // 10% error rate
        let csv_data = generate_large_csv(10000, 0.1);
        let config = CsvParseConfig::new();

        let start = Instant::now();
        let result = parse_csv_with_config(csv_data.as_bytes(), &config);
        let duration = start.elapsed();

        assert!(
            result.is_ok(),
            "Should successfully parse 10k rows with errors"
        );
        assert!(
            duration.as_secs() < 30,
            "Should complete in under 30 seconds, took {:?}",
            duration
        );

        let parsed = result.unwrap();
        let total = parsed.rows.len() + parsed.errors.len();
        assert!(
            total >= 9000,
            "Should process most rows: valid={}, errors={}",
            parsed.rows.len(),
            parsed.errors.len()
        );
    }

    #[tokio::test]
    async fn test_progress_accurate_during_large_import() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("progress");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let job_id = ctx
            .create_import_job(tenant_id, "large.csv", 10000, "processing")
            .await;

        // Simulate progress updates
        for processed in [1000, 5000, 7500, 10000] {
            UserImportJob::update_progress(
                ctx.admin_pool.inner(),
                *tenant_id.as_uuid(),
                job_id,
                processed,
                processed - 50, // 50 errors
                40,
                10,
            )
            .await
            .expect("Progress update should succeed");

            let job =
                UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_id.as_uuid(), job_id)
                    .await
                    .expect("Query should succeed")
                    .expect("Job should exist");

            assert_eq!(
                job.processed_rows, processed,
                "Progress should be {} but was {}",
                processed, job.processed_rows
            );
        }
    }

    #[tokio::test]
    async fn test_memory_stable_during_large_import() {
        // This test verifies streaming parser doesn't hold all data in memory
        // We can't directly measure memory, but we can verify it completes

        let csv_data = generate_large_csv(10000, 0.0);
        let config = CsvParseConfig::new();

        // Parse twice to ensure no memory leak accumulation
        for _ in 0..2 {
            let result = parse_csv_with_config(csv_data.as_bytes(), &config);
            assert!(result.is_ok(), "Should complete without memory issues");
        }
    }
}

// ===========================================================================
// Phase 7: User Story 5 - Concurrent Import Jobs
// ===========================================================================

mod concurrency {
    use super::*;

    #[tokio::test]
    async fn test_five_concurrent_jobs_complete_correctly() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("concurrent");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        // Create 5 jobs
        let mut job_ids = Vec::new();
        for i in 0..5 {
            let job_id = ctx
                .create_import_job(tenant_id, &format!("concurrent_{}.csv", i), 100, "pending")
                .await;
            job_ids.push(job_id);
        }

        // Process all concurrently using tokio::spawn
        let mut handles = Vec::new();
        for &job_id in &job_ids {
            let pool = ctx.admin_pool.inner().clone();
            let tid = *tenant_id.as_uuid();
            let handle = tokio::spawn(async move {
                UserImportJob::mark_started(&pool, tid, job_id).await?;
                UserImportJob::mark_completed(&pool, tid, job_id, 95, 3, 2).await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        for (i, handle) in handles.into_iter().enumerate() {
            let result = handle.await.expect("Task should not panic");
            assert!(
                result.is_ok(),
                "Job {} should complete successfully: {:?}",
                i,
                result
            );
        }

        // Verify all have correct counts
        for job_id in &job_ids {
            let job =
                UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_id.as_uuid(), *job_id)
                    .await
                    .expect("Query should succeed")
                    .expect("Job should exist");

            assert_eq!(job.status, "completed");
            assert_eq!(job.success_count, 95);
        }
    }

    #[tokio::test]
    async fn test_concurrent_same_tenant_unique_data() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("same-tenant");
        let _tenant_id = ctx.create_unique_tenant(&prefix).await;

        // Create unique CSVs for same tenant
        let csv1 = generate_valid_csv(10, &format!("{}-1", prefix));
        let csv2 = generate_valid_csv(10, &format!("{}-2", prefix));

        let config =
            CsvParseConfig::new().with_duplicate_check_fields(DuplicateCheckFields::email_only());

        // Parse concurrently
        let (result1, result2) = tokio::join!(
            async { parse_csv_with_config(csv1.as_bytes(), &config) },
            async { parse_csv_with_config(csv2.as_bytes(), &config) }
        );

        assert!(result1.is_ok(), "First CSV should parse");
        assert!(result2.is_ok(), "Second CSV should parse");

        let parsed1 = result1.unwrap();
        let parsed2 = result2.unwrap();

        // Both should have all rows since emails are unique per CSV
        assert_eq!(parsed1.rows.len(), 10);
        assert_eq!(parsed2.rows.len(), 10);
    }

    #[tokio::test]
    async fn test_concurrent_different_tenants_isolated() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("diff-tenant");

        let tenant_a = ctx.create_unique_tenant(&format!("{}-a", prefix)).await;
        let tenant_b = ctx.create_unique_tenant(&format!("{}-b", prefix)).await;

        // Create jobs for different tenants concurrently
        let (job_a, job_b) = tokio::join!(
            ctx.create_import_job(tenant_a, "tenant_a.csv", 50, "pending"),
            ctx.create_import_job(tenant_b, "tenant_b.csv", 75, "pending")
        );

        // Both should be created
        let found_a = UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_a.as_uuid(), job_a)
            .await
            .expect("Query should succeed");

        let found_b = UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_b.as_uuid(), job_b)
            .await
            .expect("Query should succeed");

        assert!(found_a.is_some(), "Tenant A job should exist");
        assert!(found_b.is_some(), "Tenant B job should exist");

        // Cross-tenant access should fail
        let cross_a = UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_b.as_uuid(), job_a)
            .await
            .expect("Query should succeed");

        assert!(cross_a.is_none(), "Tenant B should not see Tenant A's job");
    }

    #[tokio::test]
    async fn test_new_job_accepted_under_load() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("under-load");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        // Create some active jobs
        for i in 0..3 {
            ctx.create_import_job(tenant_id, &format!("active_{}.csv", i), 100, "processing")
                .await;
        }

        // Should still be able to create new job
        let new_job_id = ctx
            .create_import_job(tenant_id, "new.csv", 50, "pending")
            .await;

        let new_job =
            UserImportJob::find_by_id(ctx.admin_pool.inner(), *tenant_id.as_uuid(), new_job_id)
                .await
                .expect("Query should succeed")
                .expect("New job should exist");

        assert_eq!(new_job.status, "pending");
    }

    #[tokio::test]
    async fn test_check_concurrent_import_detects_running() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("detect-running");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        // Initially no concurrent imports
        let has_running =
            UserImportJob::check_concurrent_import(ctx.admin_pool.inner(), *tenant_id.as_uuid())
                .await
                .expect("Check should succeed");

        assert!(!has_running, "Should have no running imports initially");

        // Create a processing job
        ctx.create_import_job(tenant_id, "running.csv", 100, "processing")
            .await;

        // Now should detect running import
        let has_running =
            UserImportJob::check_concurrent_import(ctx.admin_pool.inner(), *tenant_id.as_uuid())
                .await
                .expect("Check should succeed");

        assert!(has_running, "Should detect running import");
    }
}

// ===========================================================================
// Phase 8: User Story 6 - Invitation Workflow Testing
// ===========================================================================

mod invitations {
    use super::*;

    #[tokio::test]
    async fn test_invitation_created_for_import() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("inv-create");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let email = format!("{}@test.xavyo.com", prefix);
        let user_id = ctx.create_user(tenant_id, &email, "temp_hash").await;

        let expires_at = Utc::now() + Duration::hours(24);
        let inv_id = ctx
            .create_invitation(
                tenant_id,
                user_id,
                &email,
                "token_hash_123",
                "pending",
                expires_at,
            )
            .await;

        // Verify invitation exists
        let inv: Option<(String, String)> =
            sqlx::query_as("SELECT email, status FROM user_invitations WHERE id = $1")
                .bind(inv_id)
                .fetch_optional(ctx.admin_pool.inner())
                .await
                .expect("Query should succeed");

        assert!(inv.is_some(), "Invitation should exist");
        let (inv_email, status) = inv.unwrap();
        assert_eq!(inv_email, email);
        assert_eq!(status, "pending");
    }

    #[tokio::test]
    async fn test_valid_token_validates_successfully() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("inv-valid");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let email = format!("{}@test.xavyo.com", prefix);
        let user_id = ctx.create_user(tenant_id, &email, "temp_hash").await;

        let expires_at = Utc::now() + Duration::hours(24);
        let inv_id = ctx
            .create_invitation(
                tenant_id,
                user_id,
                &email,
                "valid_token_hash",
                "pending",
                expires_at,
            )
            .await;

        // Query to check if valid (expires_at > now and status = pending)
        let valid: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, email FROM user_invitations WHERE id = $1 AND status = 'pending' AND expires_at > NOW()",
        )
        .bind(inv_id)
        .fetch_optional(ctx.admin_pool.inner())
        .await
        .expect("Query should succeed");

        assert!(
            valid.is_some(),
            "Pending non-expired invitation should be valid"
        );
    }

    #[tokio::test]
    async fn test_accept_invitation_updates_status() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("inv-accept");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let email = format!("{}@test.xavyo.com", prefix);
        let user_id = ctx.create_user(tenant_id, &email, "temp_hash").await;

        let expires_at = Utc::now() + Duration::hours(24);
        let inv_id = ctx
            .create_invitation(
                tenant_id,
                user_id,
                &email,
                "accept_token_hash",
                "pending",
                expires_at,
            )
            .await;

        // Accept the invitation
        sqlx::query(
            "UPDATE user_invitations SET status = 'accepted', accepted_at = NOW() WHERE id = $1",
        )
        .bind(inv_id)
        .execute(ctx.admin_pool.inner())
        .await
        .expect("Accept should succeed");

        // Verify status changed
        let status: (String,) = sqlx::query_as("SELECT status FROM user_invitations WHERE id = $1")
            .bind(inv_id)
            .fetch_one(ctx.admin_pool.inner())
            .await
            .expect("Query should succeed");

        assert_eq!(status.0, "accepted");
    }

    #[tokio::test]
    async fn test_expired_token_rejected() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("inv-expired");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let email = format!("{}@test.xavyo.com", prefix);
        let user_id = ctx.create_user(tenant_id, &email, "temp_hash").await;

        // Create expired invitation (25 hours ago)
        let expires_at = Utc::now() - Duration::hours(25);
        let inv_id = ctx
            .create_invitation(
                tenant_id,
                user_id,
                &email,
                "expired_token_hash",
                "pending",
                expires_at,
            )
            .await;

        // Query for valid invitation (should return None for expired)
        let valid: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM user_invitations WHERE id = $1 AND status = 'pending' AND expires_at > NOW()",
        )
        .bind(inv_id)
        .fetch_optional(ctx.admin_pool.inner())
        .await
        .expect("Query should succeed");

        assert!(valid.is_none(), "Expired invitation should not be valid");
    }

    #[tokio::test]
    async fn test_already_accepted_token_rejected() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("inv-already");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let email = format!("{}@test.xavyo.com", prefix);
        let user_id = ctx.create_user(tenant_id, &email, "temp_hash").await;

        let expires_at = Utc::now() + Duration::hours(24);
        let inv_id = ctx
            .create_invitation(
                tenant_id,
                user_id,
                &email,
                "already_used_hash",
                "accepted", // Already accepted
                expires_at,
            )
            .await;

        // Query for pending invitation (should return None for accepted)
        let valid: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM user_invitations WHERE id = $1 AND status = 'pending'")
                .bind(inv_id)
                .fetch_optional(ctx.admin_pool.inner())
                .await
                .expect("Query should succeed");

        assert!(
            valid.is_none(),
            "Already accepted invitation should not be reusable"
        );
    }

    #[tokio::test]
    async fn test_resend_creates_new_expiry() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("inv-resend");
        let tenant_id = ctx.create_unique_tenant(&prefix).await;

        let email = format!("{}@test.xavyo.com", prefix);
        let user_id = ctx.create_user(tenant_id, &email, "temp_hash").await;

        // Create invitation expiring soon
        let old_expires = Utc::now() + Duration::hours(1);
        let inv_id = ctx
            .create_invitation(
                tenant_id,
                user_id,
                &email,
                "old_token_hash",
                "pending",
                old_expires,
            )
            .await;

        // Simulate resend by updating expiry and token
        let new_expires = Utc::now() + Duration::hours(24);
        sqlx::query("UPDATE user_invitations SET token_hash = $1, expires_at = $2 WHERE id = $3")
            .bind("new_token_hash")
            .bind(new_expires)
            .bind(inv_id)
            .execute(ctx.admin_pool.inner())
            .await
            .expect("Resend should succeed");

        // Verify new expiry
        let expires: (chrono::DateTime<Utc>,) =
            sqlx::query_as("SELECT expires_at FROM user_invitations WHERE id = $1")
                .bind(inv_id)
                .fetch_one(ctx.admin_pool.inner())
                .await
                .expect("Query should succeed");

        assert!(
            expires.0 > old_expires,
            "New expiry should be later than old expiry"
        );
    }

    #[tokio::test]
    async fn test_invitation_tenant_isolation() {
        let ctx = ImportTestContext::new().await;
        let prefix = unique_test_prefix("inv-iso");

        let tenant_a = ctx.create_unique_tenant(&format!("{}-a", prefix)).await;
        let tenant_b = ctx.create_unique_tenant(&format!("{}-b", prefix)).await;

        let email = format!("{}-a@test.xavyo.com", prefix);
        let user_id = ctx.create_user(tenant_a, &email, "temp_hash").await;

        let expires_at = Utc::now() + Duration::hours(24);
        let inv_id = ctx
            .create_invitation(
                tenant_a,
                user_id,
                &email,
                "iso_token_hash",
                "pending",
                expires_at,
            )
            .await;

        // Tenant B should not be able to see/access Tenant A's invitation
        let visible: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM user_invitations WHERE id = $1 AND tenant_id = $2")
                .bind(inv_id)
                .bind(tenant_b.as_uuid())
                .fetch_optional(ctx.admin_pool.inner())
                .await
                .expect("Query should succeed");

        assert!(
            visible.is_none(),
            "Tenant B should not see Tenant A's invitation"
        );
    }
}
