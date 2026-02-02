//! Background job processor for bulk user import (F086).
//!
//! Iterates over parsed CSV rows, creates users, records errors,
//! and updates progress counters. Handles group/role assignment
//! and invitation sending when enabled.

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::services::csv_parser::{CsvParseResult, ParsedRow, RowError};
use crate::services::invitation_service::InvitationService;
use xavyo_api_auth::EmailSender;
use xavyo_db::models::{CreateImportError, Group, GroupMembership, UserImportError, UserImportJob};
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Progress update batch size (update DB counters every N rows).
const PROGRESS_BATCH_SIZE: i32 = 10;

/// Process an import job in the background.
///
/// This function runs on a spawned Tokio task. It:
/// 1. Marks the job as "processing"
/// 2. Iterates rows, creating users and recording errors
/// 3. Optionally sends invitation emails
/// 4. Updates progress counters periodically
/// 5. Marks the job as "completed" or "failed"
pub async fn process_job(
    pool: PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
    parse_result: CsvParseResult,
    send_invitations: bool,
    email_sender: Arc<dyn EmailSender>,
    event_publisher: Option<EventPublisher>,
) {
    // Mark job as started (returns None if job not in pending state)
    match UserImportJob::mark_started(&pool, tenant_id, job_id).await {
        Ok(Some(_)) => { /* proceed */ }
        Ok(None) => {
            tracing::warn!(job_id = %job_id, "Job not found or not in pending state");
            return;
        }
        Err(e) => {
            tracing::error!(job_id = %job_id, error = %e, "Failed to mark job as started");
            return;
        }
    }

    tracing::info!(
        job_id = %job_id,
        tenant_id = %tenant_id,
        total_rows = parse_result.total_rows,
        valid_rows = parse_result.rows.len(),
        parse_errors = parse_result.errors.len(),
        "Starting import processing"
    );

    // Publish import.started event
    publish_import_event(
        &event_publisher,
        "import.started",
        tenant_id,
        serde_json::json!({
            "job_id": job_id,
            "total_rows": parse_result.total_rows,
        }),
    );

    let mut success_count: i32 = 0;
    let mut error_count: i32 = 0;
    let mut skip_count: i32 = 0;
    let mut processed: i32 = 0;

    // Record pre-existing parse errors (from CSV validation)
    for row_error in &parse_result.errors {
        if let Err(e) = record_error(&pool, tenant_id, job_id, row_error).await {
            tracing::error!(job_id = %job_id, error = %e, "Failed to record parse error");
        }
        error_count += 1;
        processed += 1;
    }

    // Process each valid row
    for row in &parse_result.rows {
        match process_single_row(
            &pool,
            tenant_id,
            job_id,
            row,
            send_invitations,
            &email_sender,
        )
        .await
        {
            RowOutcome::Created => success_count += 1,
            RowOutcome::Skipped => skip_count += 1,
            RowOutcome::Error => error_count += 1,
        }
        processed += 1;

        // Update progress periodically
        if processed % PROGRESS_BATCH_SIZE == 0 {
            if let Err(e) = UserImportJob::update_progress(
                &pool,
                tenant_id,
                job_id,
                processed,
                success_count,
                error_count,
                skip_count,
            )
            .await
            {
                tracing::error!(job_id = %job_id, error = %e, "Failed to update progress");
            }
        }
    }

    // Mark job as completed with final counts
    match UserImportJob::mark_completed(
        &pool,
        tenant_id,
        job_id,
        success_count,
        error_count,
        skip_count,
    )
    .await
    {
        Ok(Some(_)) => {
            tracing::info!(
                job_id = %job_id,
                success = success_count,
                errors = error_count,
                skipped = skip_count,
                "Import job completed"
            );
            // Publish import.completed event
            publish_import_event(
                &event_publisher,
                "import.completed",
                tenant_id,
                serde_json::json!({
                    "job_id": job_id,
                    "success_count": success_count,
                    "error_count": error_count,
                    "skip_count": skip_count,
                }),
            );
        }
        Ok(None) => {
            tracing::warn!(job_id = %job_id, "Job not found when marking completed");
        }
        Err(e) => {
            tracing::error!(job_id = %job_id, error = %e, "Failed to mark job as completed");
            let _ = UserImportJob::mark_failed(&pool, tenant_id, job_id, &e.to_string()).await;
            // Publish import.failed event
            publish_import_event(
                &event_publisher,
                "import.failed",
                tenant_id,
                serde_json::json!({
                    "job_id": job_id,
                    "error": e.to_string(),
                }),
            );
        }
    }
}

/// Publish a webhook event for import lifecycle. Fire-and-forget.
fn publish_import_event(
    publisher: &Option<EventPublisher>,
    event_type: &str,
    tenant_id: Uuid,
    data: serde_json::Value,
) {
    if let Some(ref pub_ref) = publisher {
        pub_ref.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: event_type.to_string(),
            tenant_id,
            actor_id: None,
            timestamp: chrono::Utc::now(),
            data,
        });
    }
}

/// Outcome of processing a single CSV row.
enum RowOutcome {
    Created,
    Skipped,
    Error,
}

/// Process a single CSV row: check for duplicate, create user, handle errors.
async fn process_single_row(
    pool: &PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
    row: &ParsedRow,
    send_invitations: bool,
    email_sender: &Arc<dyn EmailSender>,
) -> RowOutcome {
    // Check if user already exists in this tenant
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id = $1 AND email = $2)",
    )
    .bind(tenant_id)
    .bind(&row.email)
    .fetch_one(pool)
    .await
    {
        Ok(true) => {
            // Duplicate in tenant — skip
            let err = RowError {
                line_number: row.line_number,
                email: Some(row.email.clone()),
                column_name: Some("email".to_string()),
                error_type: "duplicate_in_tenant".to_string(),
                error_message: format!(
                    "User with email '{}' already exists in this tenant",
                    row.email
                ),
            };
            let _ = record_error(pool, tenant_id, job_id, &err).await;
            return RowOutcome::Skipped;
        }
        Ok(false) => { /* proceed to create */ }
        Err(e) => {
            let err = RowError {
                line_number: row.line_number,
                email: Some(row.email.clone()),
                column_name: None,
                error_type: "system".to_string(),
                error_message: format!("Database error checking duplicate: {}", e),
            };
            let _ = record_error(pool, tenant_id, job_id, &err).await;
            return RowOutcome::Error;
        }
    }

    // Build custom_attributes JSON (includes department + any custom columns)
    let mut attr_map = serde_json::Map::new();
    for (k, v) in &row.custom_attributes {
        attr_map.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref dept) = row.department {
        attr_map.insert(
            "department".to_string(),
            serde_json::Value::String(dept.clone()),
        );
    }
    let custom_attrs = serde_json::Value::Object(attr_map);

    // Create user with empty password hash (must use invitation to set password)
    let user_result = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO users (
            tenant_id, email, password_hash, display_name, first_name, last_name,
            is_active, email_verified, custom_attributes
        )
        VALUES ($1, $2, '', $3, $4, $5, $6, false, $7)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&row.email)
    .bind(&row.display_name)
    .bind(&row.first_name)
    .bind(&row.last_name)
    .bind(row.is_active)
    .bind(&custom_attrs)
    .fetch_one(pool)
    .await;

    let user_id = match user_result {
        Ok(id) => id,
        Err(e) => {
            let err = RowError {
                line_number: row.line_number,
                email: Some(row.email.clone()),
                column_name: None,
                error_type: "system".to_string(),
                error_message: format!("Failed to create user: {}", e),
            };
            let _ = record_error(pool, tenant_id, job_id, &err).await;
            return RowOutcome::Error;
        }
    };

    // Group assignment — find or create groups, then add membership
    for group_name in &row.groups {
        if let Err(e) = assign_group(pool, tenant_id, user_id, group_name).await {
            tracing::warn!(
                user_id = %user_id,
                group = %group_name,
                error = %e,
                "Failed to assign group during import"
            );
            let err = RowError {
                line_number: row.line_number,
                email: Some(row.email.clone()),
                column_name: Some("groups".to_string()),
                error_type: "group_error".to_string(),
                error_message: format!("Failed to assign group '{}': {}", group_name, e),
            };
            let _ = record_error(pool, tenant_id, job_id, &err).await;
        }
    }

    // Role validation and assignment — validate roles exist, record errors for unknown
    for role_name in &row.roles {
        if let Err(e) =
            validate_and_record_role(pool, tenant_id, user_id, job_id, row, role_name).await
        {
            tracing::warn!(
                user_id = %user_id,
                role = %role_name,
                error = %e,
                "Failed to validate/assign role during import"
            );
        }
    }

    // Invitation sending — create invitation and send email if enabled
    if send_invitations {
        let frontend_base_url = std::env::var("FRONTEND_BASE_URL")
            .unwrap_or_else(|_| "https://app.xavyo.com".to_string());

        match InvitationService::create_invitation(pool, tenant_id, user_id, Some(job_id)).await {
            Ok((invitation, raw_token)) => {
                if let Err(e) = InvitationService::send_invitation_email(
                    email_sender,
                    &row.email,
                    &raw_token,
                    &frontend_base_url,
                )
                .await
                {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "Failed to send invitation email during import"
                    );
                } else {
                    // Mark invitation as sent
                    let _ =
                        xavyo_db::models::UserInvitation::mark_sent(pool, tenant_id, invitation.id)
                            .await;
                }
            }
            Err(e) => {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "Failed to create invitation during import"
                );
            }
        }
    }

    RowOutcome::Created
}

/// Find or create a group by display name, then add the user as a member.
async fn assign_group(
    pool: &PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
    group_name: &str,
) -> Result<(), sqlx::Error> {
    // Look up existing group by name
    let group = match Group::find_by_name(pool, tenant_id, group_name).await? {
        Some(g) => g,
        None => {
            // Create the group (auto-create on import)
            Group::create(pool, tenant_id, group_name, None, None, None, None).await?
        }
    };

    // Add user as a member (ON CONFLICT DO NOTHING handles idempotency)
    let _ = GroupMembership::add_member(pool, tenant_id, group.id, user_id).await;
    Ok(())
}

/// Validate that a role name exists as a gov_entitlement with type "role",
/// and record an error if not found.
async fn validate_and_record_role(
    pool: &PgPool,
    tenant_id: Uuid,
    _user_id: Uuid,
    job_id: Uuid,
    row: &ParsedRow,
    role_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check if a role with this name exists in the governance system
    let role_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM gov_entitlements
            WHERE tenant_id = $1 AND name = $2 AND entitlement_type = 'role'
        )
        "#,
    )
    .bind(tenant_id)
    .bind(role_name)
    .fetch_one(pool)
    .await?;

    if !role_exists {
        let err = RowError {
            line_number: row.line_number,
            email: Some(row.email.clone()),
            column_name: Some("roles".to_string()),
            error_type: "role_not_found".to_string(),
            error_message: format!("Role '{}' does not exist", role_name),
        };
        record_error(pool, tenant_id, job_id, &err).await?;
    }

    // Note: Full role assignment via gov_entitlement_assignments requires an
    // application_id context and is better handled through the governance
    // access request workflow. The import validates role names exist so
    // administrators can review and assign through the proper governance flow.

    Ok(())
}

/// Record a row error in the database.
async fn record_error(
    pool: &PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
    err: &RowError,
) -> Result<(), sqlx::Error> {
    UserImportError::create(
        pool,
        &CreateImportError {
            tenant_id,
            job_id,
            line_number: err.line_number,
            email: err.email.clone(),
            column_name: err.column_name.clone(),
            error_type: err.error_type.clone(),
            error_message: err.error_message.clone(),
        },
    )
    .await?;
    Ok(())
}
