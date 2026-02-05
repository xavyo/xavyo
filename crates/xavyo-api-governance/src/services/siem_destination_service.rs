//! SIEM Destination service (F078).
//!
//! Manages CRUD operations for SIEM export destinations
//! with credential encryption and connectivity testing.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{CreateSiemDestination, SiemDestination, UpdateSiemDestination};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for SIEM destination operations.
pub struct SiemDestinationService {
    pool: PgPool,
}

impl SiemDestinationService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List destinations for a tenant with pagination.
    pub async fn list_destinations(
        &self,
        tenant_id: Uuid,
        enabled_only: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SiemDestination>, i64)> {
        let destinations =
            SiemDestination::list_by_tenant(&self.pool, tenant_id, enabled_only, limit, offset)
                .await?;
        let total = SiemDestination::count_by_tenant(&self.pool, tenant_id, enabled_only).await?;
        Ok((destinations, total))
    }

    /// Get a destination by ID.
    pub async fn get_destination(&self, tenant_id: Uuid, id: Uuid) -> Result<SiemDestination> {
        SiemDestination::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::SiemDestinationNotFound(id))
    }

    /// Create a new destination.
    pub async fn create_destination(
        &self,
        tenant_id: Uuid,
        created_by: Uuid,
        input: CreateSiemDestination,
    ) -> Result<SiemDestination> {
        // Check for duplicate name
        if let Some(_existing) =
            SiemDestination::find_by_name(&self.pool, tenant_id, &input.name).await?
        {
            return Err(GovernanceError::SiemDestinationNameExists(
                input.name.clone(),
            ));
        }

        let destination = SiemDestination::create(&self.pool, tenant_id, created_by, input).await?;
        Ok(destination)
    }

    /// Update a destination.
    pub async fn update_destination(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateSiemDestination,
    ) -> Result<SiemDestination> {
        // Check name uniqueness if changing
        if let Some(ref new_name) = input.name {
            if let Some(existing) =
                SiemDestination::find_by_name(&self.pool, tenant_id, new_name).await?
            {
                if existing.id != id {
                    return Err(GovernanceError::SiemDestinationNameExists(new_name.clone()));
                }
            }
        }

        SiemDestination::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::SiemDestinationNotFound(id))
    }

    /// Delete a destination.
    pub async fn delete_destination(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        let deleted = SiemDestination::delete(&self.pool, tenant_id, id).await?;
        if !deleted {
            return Err(GovernanceError::SiemDestinationNotFound(id));
        }
        Ok(())
    }

    /// Test connectivity to a destination.
    /// Sends a test event and reports success/failure + latency.
    ///
    /// The `encryption_key` is needed to decrypt the stored `auth_config`
    /// so we can pass plaintext credentials to the delivery worker.
    pub async fn test_connectivity(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        encryption_key: &[u8],
    ) -> Result<(bool, Option<u64>, Option<String>)> {
        let destination = self.get_destination(tenant_id, id).await?;

        let start = std::time::Instant::now();

        let dest_type =
            xavyo_siem::models::DestinationType::from_str_value(&destination.destination_type);
        let export_fmt =
            xavyo_siem::models::ExportFormat::from_str_value(&destination.export_format);

        if dest_type.is_none() || export_fmt.is_none() {
            return Ok((
                false,
                None,
                Some(format!(
                    "Invalid destination type '{}' or format '{}'",
                    destination.destination_type, destination.export_format
                )),
            ));
        }

        let dest_type = dest_type.unwrap();
        let port = destination
            .endpoint_port
            .map_or_else(|| dest_type.default_port(), |p| p as u16);

        // Decrypt auth_config if present
        let decrypted_auth = if let Some(ref encrypted) = destination.auth_config {
            match xavyo_siem::crypto::decrypt_auth_config(encrypted, encryption_key) {
                Ok(plaintext) => Some(plaintext),
                Err(e) => {
                    return Ok((
                        false,
                        None,
                        Some(format!("Failed to decrypt auth config: {e}")),
                    ));
                }
            }
        } else {
            None
        };

        let worker = match xavyo_siem::delivery::create_worker(
            &dest_type,
            &destination.endpoint_host,
            port,
            destination.tls_verify_cert,
            decrypted_auth.as_deref(),
            destination.splunk_source.as_deref(),
            destination.splunk_sourcetype.as_deref(),
            destination.splunk_index.as_deref(),
        ) {
            Ok(w) => w,
            Err(e) => {
                return Ok((false, None, Some(e.to_string())));
            }
        };

        match worker.test_connectivity().await {
            Ok(result) => {
                let latency = start.elapsed().as_millis() as u64;
                if result.success {
                    Ok((true, Some(latency), None))
                } else {
                    Ok((false, Some(latency), result.error))
                }
            }
            Err(e) => {
                let latency = start.elapsed().as_millis() as u64;
                Ok((false, Some(latency), Some(e.to_string())))
            }
        }
    }
}
