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

    // Record pre-existing parse errors (from CSV validation). Persist
    // failures must not complete the job with a missing error list.
    for row_error in &parse_result.errors {
        if let Err(e) =
            import_error_recorded(record_error(&pool, tenant_id, job_id, row_error).await)
        {
            tracing::error!(job_id = %job_id, error = %e, "Failed to record parse error");
            fail_job_after_persist_error(
                &pool,
                tenant_id,
                job_id,
                &e.to_string(),
                &event_publisher,
            )
            .await;
            return;
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
            Ok(RowOutcome::Created) => success_count += 1,
            Ok(RowOutcome::Skipped) => skip_count += 1,
            Ok(RowOutcome::Error) => error_count += 1,
            Err(e) => {
                tracing::error!(
                    job_id = %job_id,
                    error = %e,
                    "Failed to persist import row outcome"
                );
                fail_job_after_persist_error(
                    &pool,
                    tenant_id,
                    job_id,
                    &e.to_string(),
                    &event_publisher,
                )
                .await;
                return;
            }
        }
        processed += 1;

        // Update progress periodically. Persist errors must not complete the
        // job with a stale progress snapshot.
        if processed % PROGRESS_BATCH_SIZE == 0 {
            if let Err(e) = import_progress_recorded(
                UserImportJob::update_progress(
                    &pool,
                    tenant_id,
                    job_id,
                    processed,
                    success_count,
                    error_count,
                    skip_count,
                )
                .await,
            ) {
                tracing::error!(job_id = %job_id, error = %e, "Failed to update progress");
                fail_job_after_persist_error(
                    &pool,
                    tenant_id,
                    job_id,
                    &e.to_string(),
                    &event_publisher,
                )
                .await;
                return;
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
            match import_mark_failed_result(
                UserImportJob::mark_failed(&pool, tenant_id, job_id, &e.to_string()).await,
            ) {
                Ok(_) => {
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
                Err(fail_err) => {
                    tracing::error!(
                        job_id = %job_id,
                        error = %fail_err,
                        "Failed to mark import job as failed after complete failed"
                    );
                }
            }
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

/// Mark the import job failed after a persist error so it does not stay
/// running or complete with a missing error list.
async fn fail_job_after_persist_error(
    pool: &PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
    error: &str,
    event_publisher: &Option<EventPublisher>,
) {
    match import_mark_failed_result(
        UserImportJob::mark_failed(pool, tenant_id, job_id, error).await,
    ) {
        Ok(_) => {
            publish_import_event(
                event_publisher,
                "import.failed",
                tenant_id,
                serde_json::json!({
                    "job_id": job_id,
                    "error": error,
                }),
            );
        }
        Err(fail_err) => {
            tracing::error!(
                job_id = %job_id,
                error = %fail_err,
                "Failed to mark import job as failed after persist error"
            );
        }
    }
}

/// Process a single CSV row: check for duplicate, create user, handle errors.
async fn process_single_row(
    pool: &PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
    row: &ParsedRow,
    send_invitations: bool,
    email_sender: &Arc<dyn EmailSender>,
) -> Result<RowOutcome, sqlx::Error> {
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
            import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
            return Ok(RowOutcome::Skipped);
        }
        Ok(false) => { /* proceed to create */ }
        Err(e) => {
            let err = RowError {
                line_number: row.line_number,
                email: Some(row.email.clone()),
                column_name: None,
                error_type: "system".to_string(),
                error_message: format!("Database error checking duplicate: {e}"),
            };
            import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
            return Ok(RowOutcome::Error);
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
        r"
        INSERT INTO users (
            tenant_id, email, password_hash, display_name, first_name, last_name,
            is_active, email_verified, custom_attributes
        )
        VALUES ($1, $2, '', $3, $4, $5, $6, false, $7)
        RETURNING id
        ",
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
                error_message: format!("Failed to create user: {e}"),
            };
            import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
            return Ok(RowOutcome::Error);
        }
    };

    // Group assignment — find or create groups, then add membership.
    // Failures must not count the row as Created.
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
                error_message: format!("Failed to assign group '{group_name}': {e}"),
            };
            import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
            return Ok(RowOutcome::Error);
        }
    }

    // Role validation — unknown or lookup failures must not count as Created.
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
            return Ok(RowOutcome::Error);
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
                    let err = RowError {
                        line_number: row.line_number,
                        email: Some(row.email.clone()),
                        column_name: Some("email".to_string()),
                        error_type: "invitation_error".to_string(),
                        error_message: format!("Failed to send invitation email: {e}"),
                    };
                    import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
                    return Ok(RowOutcome::Error);
                } else if let Err(e) = import_mark_sent_result(
                    xavyo_db::models::UserInvitation::mark_sent(pool, tenant_id, invitation.id)
                        .await,
                ) {
                    tracing::warn!(
                        user_id = %user_id,
                        error = %e,
                        "Failed to mark invitation sent during import"
                    );
                    let err = RowError {
                        line_number: row.line_number,
                        email: Some(row.email.clone()),
                        column_name: Some("email".to_string()),
                        error_type: "invitation_error".to_string(),
                        error_message: format!("Invitation email sent but mark_sent failed: {e}"),
                    };
                    import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
                    return Ok(RowOutcome::Error);
                }
            }
            Err(e) => {
                tracing::warn!(
                    user_id = %user_id,
                    error = %e,
                    "Failed to create invitation during import"
                );
                let err = RowError {
                    line_number: row.line_number,
                    email: Some(row.email.clone()),
                    column_name: Some("email".to_string()),
                    error_type: "invitation_error".to_string(),
                    error_message: format!("Failed to create invitation: {e}"),
                };
                import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
                return Ok(RowOutcome::Error);
            }
        }
    }

    Ok(RowOutcome::Created)
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

    // Add user as a member. ON CONFLICT DO NOTHING yields RowNotFound when
    // the membership already exists; other errors must fail the assignment.
    import_membership_result(GroupMembership::add_member(pool, tenant_id, group.id, user_id).await)
}

/// Membership insert is idempotent (`ON CONFLICT DO NOTHING`). Real DB errors
/// must fail the import row, not report the user as grouped.
pub(crate) fn import_membership_result<T>(
    result: Result<T, sqlx::Error>,
) -> Result<(), sqlx::Error> {
    match result {
        Ok(_) | Err(sqlx::Error::RowNotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Invitation `mark_sent` must not be swallowed after a successful email send.
pub(crate) fn import_mark_sent_result<T>(
    result: Result<T, sqlx::Error>,
) -> Result<(), sqlx::Error> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Completing the job failed; marking failed must not be swallowed either.
pub(crate) fn import_mark_failed_result<T>(
    result: Result<T, sqlx::Error>,
) -> Result<T, sqlx::Error> {
    result
}

/// Periodic progress persist. Errors must not complete the job with stale
/// counts.
pub(crate) fn import_progress_recorded<T>(
    result: Result<T, sqlx::Error>,
) -> Result<T, sqlx::Error> {
    result
}

/// Row-error persist must fail closed so the job does not complete with a
/// missing error list or count a fake Created/Skipped outcome.
pub(crate) fn import_error_recorded<T>(result: Result<T, sqlx::Error>) -> Result<T, sqlx::Error> {
    result
}

/// Validate that a role name exists as a `gov_entitlement` with type "role",
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
        r"
        SELECT EXISTS(
            SELECT 1 FROM gov_entitlements
            WHERE tenant_id = $1 AND name = $2 AND entitlement_type = 'role'
        )
        ",
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
            error_message: format!("Role '{role_name}' does not exist"),
        };
        import_error_recorded(record_error(pool, tenant_id, job_id, &err).await)?;
        return Err(format!("Role '{role_name}' does not exist").into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_membership_result_treats_conflict_as_ok() {
        assert!(import_membership_result(Ok::<(), sqlx::Error>(())).is_ok());
        assert!(import_membership_result(Err::<(), _>(sqlx::Error::RowNotFound)).is_ok());
        assert!(
            import_membership_result(Err::<(), _>(sqlx::Error::Protocol("db".into()))).is_err()
        );
    }

    #[test]
    fn assign_group_does_not_swallow_membership_errors() {
        let src = include_str!("job_processor.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("import_membership_result("),
            "group membership insert must fail the import row on real errors"
        );
        assert!(
            !production.contains("let _ = GroupMembership::add_member("),
            "must not swallow group membership failures"
        );
    }

    #[test]
    fn import_mark_sent_result_does_not_skip_on_error() {
        assert!(import_mark_sent_result(Ok::<(), sqlx::Error>(())).is_ok());
        assert!(import_mark_sent_result(Err::<(), _>(sqlx::Error::Protocol("db".into()))).is_err());
    }

    #[test]
    fn import_does_not_swallow_invitation_mark_sent() {
        let src = include_str!("job_processor.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("import_mark_sent_result("),
            "invitation mark_sent must fail closed"
        );
        let idx = production
            .find("UserInvitation::mark_sent")
            .expect("mark_sent");
        let window = &production[idx.saturating_sub(80)..(idx + 40).min(production.len())];
        assert!(
            window.contains("import_mark_sent_result("),
            "must not swallow mark_sent after sending the invitation email: {window}"
        );
    }

    #[test]
    fn import_mark_failed_result_does_not_skip_on_error() {
        assert!(import_mark_failed_result(Ok::<(), sqlx::Error>(())).is_ok());
        assert!(
            import_mark_failed_result(Err::<(), _>(sqlx::Error::Protocol("db".into()))).is_err()
        );
    }

    #[test]
    fn import_does_not_swallow_mark_failed_after_complete_fails() {
        let src = include_str!("job_processor.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("import_mark_failed_result("),
            "mark_failed after complete failure must fail closed"
        );
        assert!(
            !production.contains("let _ = UserImportJob::mark_failed"),
            "must not swallow mark_failed persist errors"
        );
    }

    #[test]
    fn import_error_recorded_propagates_errors() {
        assert!(import_error_recorded(Ok::<(), sqlx::Error>(())).is_ok());
        assert!(import_error_recorded(Err::<(), _>(sqlx::Error::Protocol("db".into()))).is_err());
    }

    #[test]
    fn process_single_row_does_not_swallow_row_error_persist() {
        let src = include_str!("job_processor.rs");
        let production = src.split("mod tests").next().expect("production source");
        let process = production
            .split("async fn process_single_row")
            .nth(1)
            .and_then(|s| s.split("async fn assign_group").next())
            .expect("process_single_row");
        assert!(
            process.contains("import_error_recorded("),
            "row-error persist must fail closed"
        );
        assert!(
            !process.contains("let _ = record_error"),
            "must not swallow import row error persist"
        );
        assert!(
            process.contains("Failed to send invitation email")
                && process.contains("Failed to create invitation")
                && process.contains("return Ok(RowOutcome::Error)"),
            "invitation create/send failures must not count as Created"
        );
        assert!(
            process.contains("Failed to assign group during import")
                && process.contains("return Ok(RowOutcome::Error)"),
            "group assignment failures must not count as Created"
        );
        let groups = process
            .split("Failed to assign group during import")
            .nth(1)
            .and_then(|s| s.split("Role validation").next())
            .expect("group assign error arm");
        assert!(
            groups.contains("return Ok(RowOutcome::Error)"),
            "must not continue to Created after a group assignment error"
        );
        let roles = process
            .split("Failed to validate/assign role during import")
            .nth(1)
            .and_then(|s| s.split("Invitation sending").next())
            .expect("role assign error arm");
        assert!(
            roles.contains("return Ok(RowOutcome::Error)"),
            "must not continue to Created after a role lookup error"
        );
    }

    #[test]
    fn import_progress_recorded_does_not_skip_on_error() {
        assert!(import_progress_recorded(Ok::<(), sqlx::Error>(())).is_ok());
        assert!(
            import_progress_recorded(Err::<(), _>(sqlx::Error::Protocol("db".into()))).is_err()
        );

        let src = include_str!("job_processor.rs");
        let production = src.split("mod tests").next().expect("production source");
        let process_job = production
            .split("pub async fn process_job")
            .nth(1)
            .and_then(|s| s.split("fn publish_import_event").next())
            .expect("process_job");
        assert!(
            process_job.contains("import_progress_recorded(")
                && process_job.contains("fail_job_after_persist_error("),
            "progress persist must fail closed"
        );
    }

    #[test]
    fn process_job_does_not_swallow_parse_error_persist() {
        let src = include_str!("job_processor.rs");
        let production = src.split("mod tests").next().expect("production source");
        let process_job = production
            .split("pub async fn process_job")
            .nth(1)
            .and_then(|s| s.split("fn publish_import_event").next())
            .expect("process_job");
        assert!(
            process_job.contains("import_error_recorded(")
                && process_job.contains("fail_job_after_persist_error("),
            "parse-error persist must fail closed"
        );
        assert!(
            !process_job.contains("if let Err(e) = record_error"),
            "must not complete an import with a missing parse-error list"
        );
    }
}
