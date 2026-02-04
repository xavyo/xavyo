//! License Entitlement Service (F065).
//!
//! Manages license-entitlement links and provides hooks for automatic
//! license allocation/deallocation when entitlements are granted/revoked
//! (User Story 3).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovLicenseAssignment, CreateGovLicenseEntitlementLink, GovLicenseAssignment,
    GovLicenseEntitlementLink, GovLicensePool, LicenseAssignmentSource, LicenseAuditAction,
    LicenseEntitlementLinkFilter, LicenseEntitlementLinkId, LicenseEntitlementLinkWithDetails,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::license_audit_service::{LicenseAuditService, RecordPoolEventParams};
use crate::models::license::{
    CreateLicenseEntitlementLinkRequest, EntitlementLinkListResponse, LicenseAssignmentResponse,
    LicenseEntitlementLinkResponse, ListEntitlementLinksParams,
};

// ============================================================================
// Pure business logic functions (extracted for testability)
// ============================================================================

/// Enforce pagination limits: limit is clamped to [1, 100], offset is clamped to >= 0.
///
/// Returns `(limit, offset)`.
pub(crate) fn enforce_list_limits(limit: i64, offset: i64) -> (i64, i64) {
    (limit.clamp(1, 100), offset.max(0))
}

/// Check whether `entitlement_id` already exists among `existing_links`.
///
/// Used by `create_link` to prevent duplicate pool+entitlement pairs.
pub(crate) fn has_duplicate_link(
    existing_links: &[GovLicenseEntitlementLink],
    entitlement_id: Uuid,
) -> bool {
    existing_links
        .iter()
        .any(|l| l.entitlement_id == entitlement_id)
}

/// Check whether an assignment is linked to one of the valid entitlement link IDs.
///
/// Used by `release_for_entitlement` to decide if an assignment should be released.
pub(crate) fn is_entitlement_linked_to_assignment(
    assignment_link_id: Option<Uuid>,
    valid_ids: &[Uuid],
) -> bool {
    assignment_link_id
        .is_some_and(|lid| valid_ids.contains(&lid))
}

/// Sort links by priority ascending (lower number = higher priority).
///
/// Used by `check_and_allocate` to try pools in priority order.
pub(crate) fn select_highest_priority_pool(
    mut links: Vec<GovLicenseEntitlementLink>,
) -> Vec<GovLicenseEntitlementLink> {
    links.sort_by_key(|l| l.priority);
    links
}

/// Convert a `LicenseEntitlementLinkWithDetails` to a response.
pub(crate) fn link_with_details_to_response(
    link: LicenseEntitlementLinkWithDetails,
) -> LicenseEntitlementLinkResponse {
    LicenseEntitlementLinkResponse {
        id: link.id,
        license_pool_id: link.license_pool_id,
        pool_name: link.pool_name,
        pool_vendor: link.pool_vendor,
        entitlement_id: link.entitlement_id,
        entitlement_name: link.entitlement_name,
        priority: link.priority,
        enabled: link.enabled,
        created_at: link.created_at,
        created_by: link.created_by,
    }
}

/// Service for license-entitlement link operations.
pub struct LicenseEntitlementService {
    pool: PgPool,
    audit_service: LicenseAuditService,
}

impl LicenseEntitlementService {
    /// Create a new license entitlement service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit_service: LicenseAuditService::new(pool.clone()),
            pool,
        }
    }

    /// Create a new license-entitlement link.
    ///
    /// Validates that the pool exists, the `entitlement_id` is provided,
    /// and that no duplicate link exists for the same pool+entitlement pair.
    pub async fn create_link(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        request: CreateLicenseEntitlementLinkRequest,
    ) -> Result<LicenseEntitlementLinkResponse> {
        // Validate pool exists
        let license_pool =
            GovLicensePool::find_by_id(&self.pool, tenant_id, request.license_pool_id)
                .await?
                .ok_or_else(|| GovernanceError::LicensePoolNotFound(request.license_pool_id))?;

        // Check for duplicate link (same pool + entitlement)
        let existing_links =
            GovLicenseEntitlementLink::find_by_pool(&self.pool, tenant_id, request.license_pool_id)
                .await?;

        if has_duplicate_link(&existing_links, request.entitlement_id) {
            return Err(GovernanceError::Validation(format!(
                "A link already exists between pool '{}' and entitlement '{}'",
                request.license_pool_id, request.entitlement_id
            )));
        }

        // Create the link
        let input = CreateGovLicenseEntitlementLink {
            license_pool_id: request.license_pool_id,
            entitlement_id: request.entitlement_id,
            priority: Some(request.priority),
            enabled: Some(true),
            created_by: actor_id,
        };

        let created = GovLicenseEntitlementLink::create(&self.pool, tenant_id, &input).await?;

        // Log audit event
        self.audit_service
            .record_pool_event(
                tenant_id,
                RecordPoolEventParams {
                    pool_id: request.license_pool_id,
                    action: LicenseAuditAction::LinkCreated,
                    actor_id,
                    details: Some(serde_json::json!({
                        "link_id": created.id,
                        "entitlement_id": request.entitlement_id,
                        "priority": request.priority
                    })),
                },
            )
            .await?;

        // Enrich response with pool details
        let mut response = LicenseEntitlementLinkResponse::from(created);
        response.pool_name = Some(license_pool.name);
        response.pool_vendor = Some(license_pool.vendor);

        Ok(response)
    }

    /// Delete a license-entitlement link by ID.
    ///
    /// Verifies the link exists before deletion and logs an audit event.
    pub async fn delete_link(
        &self,
        tenant_id: Uuid,
        link_id: Uuid,
        actor_id: Uuid,
    ) -> Result<bool> {
        // Verify link exists
        let link_typed_id: LicenseEntitlementLinkId = link_id.into();
        let existing = GovLicenseEntitlementLink::find_by_id(&self.pool, tenant_id, link_typed_id)
            .await?
            .ok_or_else(|| GovernanceError::LicenseEntitlementLinkNotFound(link_id))?;

        // Delete the link
        let deleted =
            GovLicenseEntitlementLink::delete(&self.pool, tenant_id, link_typed_id).await?;

        if deleted {
            // Log audit event
            self.audit_service
                .record_pool_event(
                    tenant_id,
                    RecordPoolEventParams {
                        pool_id: existing.license_pool_id,
                        action: LicenseAuditAction::LinkDeleted,
                        actor_id,
                        details: Some(serde_json::json!({
                            "link_id": link_id,
                            "entitlement_id": existing.entitlement_id
                        })),
                    },
                )
                .await?;
        }

        Ok(deleted)
    }

    /// List license-entitlement links with filtering and pagination.
    pub async fn list_links(
        &self,
        tenant_id: Uuid,
        params: ListEntitlementLinksParams,
    ) -> Result<EntitlementLinkListResponse> {
        // Enforce reasonable limits
        let (limit, offset) = enforce_list_limits(params.limit, params.offset);

        let filter = LicenseEntitlementLinkFilter {
            license_pool_id: params.license_pool_id,
            entitlement_id: params.entitlement_id,
            enabled: params.enabled,
        };

        let links = GovLicenseEntitlementLink::list_with_details(
            &self.pool, tenant_id, &filter, limit, offset,
        )
        .await?;

        let total = GovLicenseEntitlementLink::count(&self.pool, tenant_id, &filter).await?;

        Ok(EntitlementLinkListResponse {
            items: links
                .into_iter()
                .map(link_with_details_to_response)
                .collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a link by ID.
    pub async fn get_link(
        &self,
        tenant_id: Uuid,
        link_id: Uuid,
    ) -> Result<Option<LicenseEntitlementLinkResponse>> {
        let link_typed_id: LicenseEntitlementLinkId = link_id.into();
        let link =
            GovLicenseEntitlementLink::find_by_id(&self.pool, tenant_id, link_typed_id).await?;
        Ok(link.map(LicenseEntitlementLinkResponse::from))
    }

    /// Get a link by ID, returning an error if not found.
    pub async fn get_link_required(
        &self,
        tenant_id: Uuid,
        link_id: Uuid,
    ) -> Result<LicenseEntitlementLinkResponse> {
        self.get_link(tenant_id, link_id)
            .await?
            .ok_or_else(|| GovernanceError::LicenseEntitlementLinkNotFound(link_id))
    }

    /// Pre-assignment hook for entitlement workflow.
    ///
    /// When a user is granted an entitlement, this method checks if that
    /// entitlement has any linked license pools and attempts to allocate
    /// a license from the highest-priority pool with available capacity.
    ///
    /// Returns:
    /// - `Ok(Some(assignment))` if a license was successfully allocated
    /// - `Ok(None)` if no links exist (entitlement doesn't require a license)
    /// - `Err(LicensePoolNoCapacity)` if links exist but no pool has capacity
    pub async fn check_and_allocate(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Option<LicenseAssignmentResponse>> {
        // Find enabled links for this entitlement with available pool capacity
        let available_links = GovLicenseEntitlementLink::find_available_for_entitlement(
            &self.pool,
            tenant_id,
            entitlement_id,
        )
        .await?;

        // If no links exist, entitlement doesn't require a license
        if available_links.is_empty() {
            // Check if there are any links at all (disabled or at capacity)
            let all_links = GovLicenseEntitlementLink::find_by_entitlement(
                &self.pool,
                tenant_id,
                entitlement_id,
            )
            .await?;

            if all_links.is_empty() {
                // No links configured at all - entitlement doesn't require a license
                return Ok(None);
            }

            // Links exist but none have capacity
            return Err(GovernanceError::LicensePoolNoCapacity(
                all_links[0].license_pool_id,
            ));
        }

        // Sort by priority (the DB already returns them sorted, but we
        // apply the pure function to be explicit about the contract)
        let sorted_links = select_highest_priority_pool(available_links);

        // Try to allocate from highest priority pool (links are ordered by priority ASC)
        for link in &sorted_links {
            // Atomically try to increment the pool's allocated count
            let incremented =
                GovLicensePool::increment_allocated(&self.pool, tenant_id, link.license_pool_id)
                    .await?;

            if incremented.is_some() {
                // Create the assignment with source = Entitlement
                let input = CreateGovLicenseAssignment {
                    license_pool_id: link.license_pool_id,
                    user_id,
                    assigned_by: user_id, // System-driven, actor is the user
                    source: LicenseAssignmentSource::Entitlement,
                    entitlement_link_id: Some(link.id),
                    session_id: None,
                    notes: Some(format!(
                        "Auto-allocated via entitlement link (entitlement: {entitlement_id})"
                    )),
                };

                let assignment = GovLicenseAssignment::create(&self.pool, tenant_id, input).await?;

                // Log audit event
                self.audit_service
                    .log_license_assigned(
                        tenant_id,
                        link.license_pool_id,
                        assignment.id,
                        user_id,
                        user_id,
                        "entitlement",
                    )
                    .await?;

                let mut response = LicenseAssignmentResponse::from(assignment);
                // Enrich with pool name from the incremented pool
                if let Some(ref pool) = incremented {
                    response.pool_name = Some(pool.name.clone());
                }

                return Ok(Some(response));
            }
            // If increment failed (race condition / no capacity), try next pool
        }

        // All pools exhausted
        Err(GovernanceError::LicensePoolNoCapacity(
            sorted_links[0].license_pool_id,
        ))
    }

    /// Post-revocation cleanup for entitlement-based assignments.
    ///
    /// When a user's entitlement is revoked, this method finds all active
    /// license assignments that were allocated via that entitlement and
    /// releases them, decrementing the pool counts accordingly.
    ///
    /// Returns the count of released assignments.
    pub async fn release_for_entitlement(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<i32> {
        // Find active entitlement-based assignments for this user
        let active_assignments = GovLicenseAssignment::find_active_entitlement_assignments(
            &self.pool, tenant_id, user_id,
        )
        .await?;

        // Find links for this entitlement to match against
        let entitlement_links =
            GovLicenseEntitlementLink::find_by_entitlement(&self.pool, tenant_id, entitlement_id)
                .await?;

        let entitlement_link_ids: Vec<Uuid> = entitlement_links.iter().map(|l| l.id).collect();

        let mut released_count: i32 = 0;

        for assignment in &active_assignments {
            // Only release assignments linked to this entitlement's links
            if !is_entitlement_linked_to_assignment(
                assignment.entitlement_link_id,
                &entitlement_link_ids,
            ) {
                continue;
            }

            // Release the assignment
            let released =
                GovLicenseAssignment::release(&self.pool, tenant_id, assignment.id).await?;

            if released.is_some() {
                // Decrement pool count
                let _ = GovLicensePool::decrement_allocated(
                    &self.pool,
                    tenant_id,
                    assignment.license_pool_id,
                )
                .await;

                // Log audit event
                let _ = self
                    .audit_service
                    .log_license_deallocated(
                        tenant_id,
                        assignment.license_pool_id,
                        assignment.id,
                        user_id,
                        user_id, // System-driven
                    )
                    .await;

                released_count += 1;
            }
        }

        Ok(released_count)
    }

    /// Enable or disable a link.
    pub async fn set_link_enabled(
        &self,
        tenant_id: Uuid,
        link_id: Uuid,
        enabled: bool,
        actor_id: Uuid,
    ) -> Result<LicenseEntitlementLinkResponse> {
        let link_typed_id: LicenseEntitlementLinkId = link_id.into();

        let updated =
            GovLicenseEntitlementLink::set_enabled(&self.pool, tenant_id, link_typed_id, enabled)
                .await?
                .ok_or_else(|| GovernanceError::LicenseEntitlementLinkNotFound(link_id))?;

        // Log audit event
        self.audit_service
            .record_pool_event(
                tenant_id,
                RecordPoolEventParams {
                    pool_id: updated.license_pool_id,
                    action: LicenseAuditAction::LinkUpdated,
                    actor_id,
                    details: Some(serde_json::json!({
                        "link_id": link_id,
                        "action": if enabled { "enabled" } else { "disabled" },
                        "enabled": enabled
                    })),
                },
            )
            .await?;

        Ok(LicenseEntitlementLinkResponse::from(updated))
    }

    /// Update the priority of a link.
    pub async fn update_link_priority(
        &self,
        tenant_id: Uuid,
        link_id: Uuid,
        priority: i32,
        actor_id: Uuid,
    ) -> Result<LicenseEntitlementLinkResponse> {
        let link_typed_id: LicenseEntitlementLinkId = link_id.into();

        let updated = GovLicenseEntitlementLink::update_priority(
            &self.pool,
            tenant_id,
            link_typed_id,
            priority,
        )
        .await?
        .ok_or_else(|| GovernanceError::LicenseEntitlementLinkNotFound(link_id))?;

        // Log audit event
        self.audit_service
            .record_pool_event(
                tenant_id,
                RecordPoolEventParams {
                    pool_id: updated.license_pool_id,
                    action: LicenseAuditAction::LinkUpdated,
                    actor_id,
                    details: Some(serde_json::json!({
                        "link_id": link_id,
                        "action": "priority_updated",
                        "priority": priority
                    })),
                },
            )
            .await?;

        Ok(LicenseEntitlementLinkResponse::from(updated))
    }

    /// Get the underlying database pool reference.
    #[must_use] 
    pub fn db_pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the audit service reference.
    #[must_use] 
    pub fn audit_service(&self) -> &LicenseAuditService {
        &self.audit_service
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::license::{
        CreateLicenseEntitlementLinkRequest, LicenseEntitlementLinkResponse,
        ListEntitlementLinksParams,
    };

    /// Helper: build a `GovLicenseEntitlementLink` with the given entitlement_id and priority.
    fn make_link(entitlement_id: Uuid, priority: i32) -> GovLicenseEntitlementLink {
        GovLicenseEntitlementLink {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            license_pool_id: Uuid::new_v4(),
            entitlement_id,
            priority,
            enabled: true,
            created_at: chrono::Utc::now(),
            created_by: Uuid::new_v4(),
        }
    }

    // ========================================================================
    // enforce_list_limits tests
    // ========================================================================

    #[test]
    fn test_enforce_list_limits_clamps_limit_to_max_100() {
        let (limit, _) = enforce_list_limits(500, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_list_limits_clamps_limit_to_min_1() {
        let (limit, _) = enforce_list_limits(0, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_negative_limit_becomes_1() {
        let (limit, _) = enforce_list_limits(-5, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_valid_limit_passes_through() {
        let (limit, _) = enforce_list_limits(50, 0);
        assert_eq!(limit, 50);
    }

    #[test]
    fn test_enforce_list_limits_boundary_1() {
        let (limit, _) = enforce_list_limits(1, 0);
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_enforce_list_limits_boundary_100() {
        let (limit, _) = enforce_list_limits(100, 0);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_enforce_list_limits_negative_offset_becomes_0() {
        let (_, offset) = enforce_list_limits(20, -10);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_enforce_list_limits_valid_offset_passes_through() {
        let (_, offset) = enforce_list_limits(20, 50);
        assert_eq!(offset, 50);
    }

    #[test]
    fn test_enforce_list_limits_zero_offset_stays_zero() {
        let (_, offset) = enforce_list_limits(20, 0);
        assert_eq!(offset, 0);
    }

    // ========================================================================
    // has_duplicate_link tests
    // ========================================================================

    #[test]
    fn test_has_duplicate_link_no_existing_links() {
        let existing: Vec<GovLicenseEntitlementLink> = vec![];
        let target = Uuid::new_v4();
        assert!(!has_duplicate_link(&existing, target));
    }

    #[test]
    fn test_has_duplicate_link_existing_with_different_entitlement() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let existing = vec![make_link(other, 0)];
        assert!(!has_duplicate_link(&existing, target));
    }

    #[test]
    fn test_has_duplicate_link_existing_with_same_entitlement() {
        let target = Uuid::new_v4();
        let existing = vec![make_link(target, 0)];
        assert!(has_duplicate_link(&existing, target));
    }

    #[test]
    fn test_has_duplicate_link_multiple_links_one_matching() {
        let target = Uuid::new_v4();
        let existing = vec![
            make_link(Uuid::new_v4(), 0),
            make_link(target, 1),
            make_link(Uuid::new_v4(), 2),
        ];
        assert!(has_duplicate_link(&existing, target));
    }

    #[test]
    fn test_has_duplicate_link_multiple_links_none_matching() {
        let target = Uuid::new_v4();
        let existing = vec![
            make_link(Uuid::new_v4(), 0),
            make_link(Uuid::new_v4(), 1),
            make_link(Uuid::new_v4(), 2),
        ];
        assert!(!has_duplicate_link(&existing, target));
    }

    // ========================================================================
    // is_entitlement_linked_to_assignment tests
    // ========================================================================

    #[test]
    fn test_is_entitlement_linked_none_link_id() {
        let valid_ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        assert!(!is_entitlement_linked_to_assignment(None, &valid_ids));
    }

    #[test]
    fn test_is_entitlement_linked_some_id_in_list() {
        let id = Uuid::new_v4();
        let valid_ids = vec![Uuid::new_v4(), id, Uuid::new_v4()];
        assert!(is_entitlement_linked_to_assignment(Some(id), &valid_ids));
    }

    #[test]
    fn test_is_entitlement_linked_some_id_not_in_list() {
        let id = Uuid::new_v4();
        let valid_ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        assert!(!is_entitlement_linked_to_assignment(Some(id), &valid_ids));
    }

    #[test]
    fn test_is_entitlement_linked_empty_valid_list() {
        let id = Uuid::new_v4();
        let valid_ids: Vec<Uuid> = vec![];
        assert!(!is_entitlement_linked_to_assignment(Some(id), &valid_ids));
    }

    #[test]
    fn test_is_entitlement_linked_none_and_empty_list() {
        let valid_ids: Vec<Uuid> = vec![];
        assert!(!is_entitlement_linked_to_assignment(None, &valid_ids));
    }

    // ========================================================================
    // select_highest_priority_pool tests
    // ========================================================================

    #[test]
    fn test_select_highest_priority_pool_sorted_correctly() {
        let ent = Uuid::new_v4();
        let links = vec![
            make_link(ent, 10),
            make_link(ent, 0),
            make_link(ent, 5),
            make_link(ent, 1),
        ];

        let sorted = select_highest_priority_pool(links);

        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0].priority, 0);
        assert_eq!(sorted[1].priority, 1);
        assert_eq!(sorted[2].priority, 5);
        assert_eq!(sorted[3].priority, 10);
    }

    #[test]
    fn test_select_highest_priority_pool_empty_list() {
        let sorted = select_highest_priority_pool(vec![]);
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_select_highest_priority_pool_single_item() {
        let ent = Uuid::new_v4();
        let link = make_link(ent, 7);
        let expected_id = link.id;
        let sorted = select_highest_priority_pool(vec![link]);

        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].id, expected_id);
        assert_eq!(sorted[0].priority, 7);
    }

    #[test]
    fn test_select_highest_priority_pool_already_sorted() {
        let ent = Uuid::new_v4();
        let links = vec![make_link(ent, 0), make_link(ent, 1), make_link(ent, 2)];

        let sorted = select_highest_priority_pool(links);

        assert_eq!(sorted[0].priority, 0);
        assert_eq!(sorted[1].priority, 1);
        assert_eq!(sorted[2].priority, 2);
    }

    #[test]
    fn test_select_highest_priority_pool_equal_priorities() {
        let ent = Uuid::new_v4();
        let links = vec![make_link(ent, 5), make_link(ent, 5), make_link(ent, 5)];

        let sorted = select_highest_priority_pool(links);
        // All have the same priority; sort is stable so order is preserved
        assert_eq!(sorted.len(), 3);
        for l in &sorted {
            assert_eq!(l.priority, 5);
        }
    }

    // ========================================================================
    // link_with_details_to_response tests
    // ========================================================================

    #[test]
    fn test_link_with_details_to_response_maps_all_fields() {
        let link = LicenseEntitlementLinkWithDetails {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            license_pool_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            priority: 2,
            enabled: true,
            created_at: chrono::Utc::now(),
            created_by: Uuid::new_v4(),
            pool_name: Some("Test Pool".to_string()),
            pool_vendor: Some("Test Vendor".to_string()),
            entitlement_name: Some("Test Entitlement".to_string()),
        };

        let response = link_with_details_to_response(link.clone());

        assert_eq!(response.id, link.id);
        assert_eq!(response.license_pool_id, link.license_pool_id);
        assert_eq!(response.pool_name.as_deref(), Some("Test Pool"));
        assert_eq!(response.pool_vendor.as_deref(), Some("Test Vendor"));
        assert_eq!(response.entitlement_id, link.entitlement_id);
        assert_eq!(
            response.entitlement_name.as_deref(),
            Some("Test Entitlement")
        );
        assert_eq!(response.priority, 2);
        assert!(response.enabled);
        assert_eq!(response.created_at, link.created_at);
        assert_eq!(response.created_by, link.created_by);
    }

    #[test]
    fn test_link_with_details_to_response_none_optional_fields() {
        let link = LicenseEntitlementLinkWithDetails {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            license_pool_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            priority: 0,
            enabled: false,
            created_at: chrono::Utc::now(),
            created_by: Uuid::new_v4(),
            pool_name: None,
            pool_vendor: None,
            entitlement_name: None,
        };

        let response = link_with_details_to_response(link);

        assert!(response.pool_name.is_none());
        assert!(response.pool_vendor.is_none());
        assert!(response.entitlement_name.is_none());
        assert!(!response.enabled);
        assert_eq!(response.priority, 0);
    }

    #[test]
    fn test_link_with_details_to_response_excludes_tenant_id() {
        // The response type does not include tenant_id; ensure the
        // conversion does not accidentally leak it via any field.
        let tenant_id = Uuid::new_v4();
        let link = LicenseEntitlementLinkWithDetails {
            id: Uuid::new_v4(),
            tenant_id,
            license_pool_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            priority: 0,
            enabled: true,
            created_at: chrono::Utc::now(),
            created_by: Uuid::new_v4(),
            pool_name: None,
            pool_vendor: None,
            entitlement_name: None,
        };

        let response = link_with_details_to_response(link);
        let json = serde_json::to_string(&response).unwrap();
        // tenant_id should not appear in the serialized response
        assert!(!json.contains(&tenant_id.to_string()));
    }

    // ========================================================================
    // Serde deserialization tests (kept as meaningful)
    // ========================================================================

    #[test]
    fn test_create_link_request_from_json_defaults() {
        let json = format!(
            r#"{{"license_pool_id": "{}", "entitlement_id": "{}"}}"#,
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let request: CreateLicenseEntitlementLinkRequest = serde_json::from_str(&json).unwrap();
        // default priority is 0
        assert_eq!(request.priority, 0);
    }

    #[test]
    fn test_create_link_request_from_json_with_priority() {
        let pool_id = Uuid::new_v4();
        let entitlement_id = Uuid::new_v4();

        let json = format!(
            r#"{{
                "license_pool_id": "{}",
                "entitlement_id": "{}",
                "priority": 5
            }}"#,
            pool_id, entitlement_id
        );

        let request: CreateLicenseEntitlementLinkRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.license_pool_id, pool_id);
        assert_eq!(request.entitlement_id, entitlement_id);
        assert_eq!(request.priority, 5);
    }

    #[test]
    fn test_list_params_from_json_empty() {
        let json = r#"{}"#;
        let params: ListEntitlementLinksParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.limit, 20); // default_limit()
        assert_eq!(params.offset, 0);
        assert!(params.license_pool_id.is_none());
        assert!(params.entitlement_id.is_none());
        assert!(params.enabled.is_none());
    }

    #[test]
    fn test_list_params_roundtrip_serialization() {
        let pool_id = Uuid::new_v4();
        let entitlement_id = Uuid::new_v4();
        let params = ListEntitlementLinksParams {
            license_pool_id: Some(pool_id),
            entitlement_id: Some(entitlement_id),
            enabled: Some(true),
            limit: 30,
            offset: 15,
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: ListEntitlementLinksParams = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.license_pool_id, Some(pool_id));
        assert_eq!(deserialized.entitlement_id, Some(entitlement_id));
        assert_eq!(deserialized.enabled, Some(true));
        assert_eq!(deserialized.limit, 30);
        assert_eq!(deserialized.offset, 15);
    }

    #[test]
    fn test_link_response_serialization() {
        let response = LicenseEntitlementLinkResponse {
            id: Uuid::new_v4(),
            license_pool_id: Uuid::new_v4(),
            pool_name: Some("Test Pool".to_string()),
            pool_vendor: Some("Test Vendor".to_string()),
            entitlement_id: Uuid::new_v4(),
            entitlement_name: Some("Test Entitlement".to_string()),
            priority: 1,
            enabled: true,
            created_at: chrono::Utc::now(),
            created_by: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"priority\":1"));
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"pool_name\":\"Test Pool\""));
    }
}
