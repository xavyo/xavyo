//! Report schedule service for compliance reporting.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateReportSchedule, GovReportSchedule, GovReportTemplate, OutputFormat, ReportScheduleFilter,
    ScheduleFrequency, ScheduleStatus, UpdateReportSchedule,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for report schedule operations.
pub struct ReportScheduleService {
    pool: PgPool,
}

impl ReportScheduleService {
    /// Create a new report schedule service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a schedule by ID.
    pub async fn get(&self, tenant_id: Uuid, schedule_id: Uuid) -> Result<GovReportSchedule> {
        GovReportSchedule::find_by_id(&self.pool, tenant_id, schedule_id)
            .await?
            .ok_or(GovernanceError::ReportScheduleNotFound(schedule_id))
    }

    /// List schedules with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        template_id: Option<Uuid>,
        status: Option<ScheduleStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovReportSchedule>, i64)> {
        let filter = ReportScheduleFilter {
            template_id,
            status,
            created_by: None,
        };

        let schedules =
            GovReportSchedule::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovReportSchedule::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((schedules, total))
    }

    /// Create a new schedule.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        name: String,
        frequency: ScheduleFrequency,
        schedule_hour: i32,
        schedule_day_of_week: Option<i32>,
        schedule_day_of_month: Option<i32>,
        parameters: Option<serde_json::Value>,
        recipients: Vec<String>,
        output_format: OutputFormat,
        created_by: Uuid,
    ) -> Result<GovReportSchedule> {
        // Validate template exists
        self.validate_template(tenant_id, template_id).await?;

        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Schedule name cannot be empty".to_string(),
            ));
        }

        // Check for duplicate name
        if GovReportSchedule::find_by_name(&self.pool, tenant_id, &name)
            .await?
            .is_some()
        {
            return Err(GovernanceError::ReportScheduleNameExists(name));
        }

        // Validate schedule parameters
        self.validate_schedule_params(
            frequency,
            schedule_hour,
            schedule_day_of_week,
            schedule_day_of_month,
        )?;

        // Validate recipients
        self.validate_recipients(&recipients)?;

        let input = CreateReportSchedule {
            template_id,
            name,
            frequency,
            schedule_hour,
            schedule_day_of_week,
            schedule_day_of_month,
            parameters,
            recipients,
            output_format,
            created_by,
        };

        GovReportSchedule::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a schedule.
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
        name: Option<String>,
        frequency: Option<ScheduleFrequency>,
        schedule_hour: Option<i32>,
        schedule_day_of_week: Option<i32>,
        schedule_day_of_month: Option<i32>,
        parameters: Option<serde_json::Value>,
        recipients: Option<Vec<String>>,
        output_format: Option<OutputFormat>,
    ) -> Result<GovReportSchedule> {
        // Get existing schedule
        let existing = self.get(tenant_id, schedule_id).await?;

        // Validate name if provided
        if let Some(ref new_name) = name {
            if new_name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Schedule name cannot be empty".to_string(),
                ));
            }

            if new_name != &existing.name
                && GovReportSchedule::find_by_name(&self.pool, tenant_id, new_name)
                    .await?
                    .is_some()
            {
                return Err(GovernanceError::ReportScheduleNameExists(new_name.clone()));
            }
        }

        // Determine effective frequency for validation
        let effective_frequency = frequency.unwrap_or(existing.frequency);
        let effective_hour = schedule_hour.unwrap_or(existing.schedule_hour);
        let effective_dow = schedule_day_of_week.or(existing.schedule_day_of_week);
        let effective_dom = schedule_day_of_month.or(existing.schedule_day_of_month);

        // Validate schedule parameters
        self.validate_schedule_params(
            effective_frequency,
            effective_hour,
            effective_dow,
            effective_dom,
        )?;

        // Validate recipients if provided
        if let Some(ref recips) = recipients {
            self.validate_recipients(recips)?;
        }

        let input = UpdateReportSchedule {
            name,
            frequency,
            schedule_hour,
            schedule_day_of_week,
            schedule_day_of_month,
            parameters,
            recipients,
            output_format,
        };

        GovReportSchedule::update(&self.pool, tenant_id, schedule_id, input)
            .await?
            .ok_or(GovernanceError::ReportScheduleNotFound(schedule_id))
    }

    /// Delete a schedule.
    pub async fn delete(&self, tenant_id: Uuid, schedule_id: Uuid) -> Result<()> {
        // Verify it exists
        let _existing = self.get(tenant_id, schedule_id).await?;

        GovReportSchedule::delete(&self.pool, tenant_id, schedule_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// Pause a schedule.
    pub async fn pause(&self, tenant_id: Uuid, schedule_id: Uuid) -> Result<GovReportSchedule> {
        let existing = self.get(tenant_id, schedule_id).await?;

        if existing.status == ScheduleStatus::Paused {
            return Err(GovernanceError::ReportScheduleAlreadyPaused(schedule_id));
        }

        GovReportSchedule::pause(&self.pool, tenant_id, schedule_id)
            .await?
            .ok_or(GovernanceError::ReportScheduleNotFound(schedule_id))
    }

    /// Resume a paused schedule.
    pub async fn resume(&self, tenant_id: Uuid, schedule_id: Uuid) -> Result<GovReportSchedule> {
        let existing = self.get(tenant_id, schedule_id).await?;

        if existing.status == ScheduleStatus::Active {
            return Err(GovernanceError::ReportScheduleAlreadyActive(schedule_id));
        }

        GovReportSchedule::resume(&self.pool, tenant_id, schedule_id)
            .await?
            .ok_or(GovernanceError::ReportScheduleNotFound(schedule_id))
    }

    /// List schedules that are due for execution (no tenant filter - global).
    pub async fn list_due(&self, _tenant_id: Uuid) -> Result<Vec<GovReportSchedule>> {
        GovReportSchedule::list_due(&self.pool)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Record a successful run.
    pub async fn record_success(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
    ) -> Result<GovReportSchedule> {
        GovReportSchedule::record_success(&self.pool, tenant_id, schedule_id)
            .await?
            .ok_or(GovernanceError::ReportScheduleNotFound(schedule_id))
    }

    /// Record a failed run.
    pub async fn record_failure(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
        error: String,
    ) -> Result<GovReportSchedule> {
        GovReportSchedule::record_failure(&self.pool, tenant_id, schedule_id, &error)
            .await?
            .ok_or(GovernanceError::ReportScheduleNotFound(schedule_id))
    }

    /// Validate schedule parameters.
    fn validate_schedule_params(
        &self,
        frequency: ScheduleFrequency,
        schedule_hour: i32,
        schedule_day_of_week: Option<i32>,
        schedule_day_of_month: Option<i32>,
    ) -> Result<()> {
        // Validate hour (0-23)
        if !(0..=23).contains(&schedule_hour) {
            return Err(GovernanceError::InvalidScheduleHour(schedule_hour));
        }

        match frequency {
            ScheduleFrequency::Daily => {
                // No additional validation needed
            }
            ScheduleFrequency::Weekly => {
                let dow = schedule_day_of_week.ok_or(GovernanceError::MissingScheduleDayOfWeek)?;
                if !(0..=6).contains(&dow) {
                    return Err(GovernanceError::InvalidScheduleDayOfWeek(dow));
                }
            }
            ScheduleFrequency::Monthly => {
                let dom =
                    schedule_day_of_month.ok_or(GovernanceError::MissingScheduleDayOfMonth)?;
                if !(1..=28).contains(&dom) {
                    return Err(GovernanceError::InvalidScheduleDayOfMonth(dom));
                }
            }
        }

        Ok(())
    }

    /// Validate recipient emails.
    fn validate_recipients(&self, recipients: &[String]) -> Result<()> {
        if recipients.is_empty() {
            return Err(GovernanceError::NoRecipientsSpecified);
        }

        for email in recipients {
            if !is_valid_email(email) {
                return Err(GovernanceError::InvalidRecipientEmail(email.clone()));
            }
        }

        Ok(())
    }

    /// Validate template exists and is accessible.
    async fn validate_template(&self, tenant_id: Uuid, template_id: Uuid) -> Result<()> {
        GovReportTemplate::find_by_id_for_tenant(&self.pool, tenant_id, template_id)
            .await?
            .ok_or(GovernanceError::ReportTemplateNotFound(template_id))?;

        Ok(())
    }
}

/// Simple email validation.
fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    if local.is_empty() || domain.is_empty() {
        return false;
    }

    if !domain.contains('.') {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user.name@domain.org"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("test@"));
        assert!(!is_valid_email("test@domain"));
    }
}
