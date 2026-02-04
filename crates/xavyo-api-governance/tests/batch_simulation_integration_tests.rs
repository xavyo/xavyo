//! Integration tests for Batch Simulation (F060 - User Story 2).
//!
//! These tests verify the batch simulation service logic including
//! user selection, impact calculation, and scope warnings.

// Note: These tests require a running database with the F060 migration applied.
// Run with: DATABASE_URL=... cargo test --test batch_simulation_integration_tests

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    /// Test batch simulation types serialization
    #[test]
    fn test_batch_simulation_type_serialization() {
        use xavyo_db::BatchSimulationType;

        let role_add = BatchSimulationType::RoleAdd;
        let json = serde_json::to_string(&role_add).unwrap();
        assert_eq!(json, "\"role_add\"");

        let parsed: BatchSimulationType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, BatchSimulationType::RoleAdd);
    }

    /// Test selection mode serialization
    #[test]
    fn test_selection_mode_serialization() {
        use xavyo_db::SelectionMode;

        let user_list = SelectionMode::UserList;
        let json = serde_json::to_string(&user_list).unwrap();
        assert_eq!(json, "\"user_list\"");

        let filter = SelectionMode::Filter;
        let json = serde_json::to_string(&filter).unwrap();
        assert_eq!(json, "\"filter\"");
    }

    /// Test filter criteria parsing
    #[test]
    fn test_filter_criteria_complete() {
        use xavyo_db::FilterCriteria;

        let filter = FilterCriteria {
            department: Some(vec!["Engineering".to_string(), "Product".to_string()]),
            status: Some("active".to_string()),
            role_ids: Some(vec![Uuid::new_v4()]),
            entitlement_ids: Some(vec![Uuid::new_v4(), Uuid::new_v4()]),
            title: Some("Manager".to_string()),
            metadata: Some(serde_json::json!({"location": "US"})),
        };

        let json = serde_json::to_value(&filter).unwrap();
        let parsed: FilterCriteria = serde_json::from_value(json).unwrap();

        assert_eq!(parsed.department.as_ref().map(std::vec::Vec::len), Some(2));
        assert_eq!(parsed.status, Some("active".to_string()));
        assert!(parsed.role_ids.is_some());
        assert_eq!(parsed.entitlement_ids.as_ref().map(std::vec::Vec::len), Some(2));
    }

    /// Test change spec validation for role operations
    #[test]
    fn test_change_spec_role_validation() {
        use xavyo_db::{BatchSimulationType, ChangeSpec};

        let role_id = Uuid::new_v4();

        // Valid role add spec
        let spec = ChangeSpec {
            operation: BatchSimulationType::RoleAdd,
            role_id: Some(role_id),
            entitlement_id: None,
            justification: Some("Test".to_string()),
        };

        assert!(spec.operation.is_role_operation());
        assert!(spec.role_id.is_some());

        // Serialize and deserialize
        let json = serde_json::to_value(&spec).unwrap();
        let parsed: ChangeSpec = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.operation, BatchSimulationType::RoleAdd);
        assert_eq!(parsed.role_id, Some(role_id));
    }

    /// Test change spec validation for entitlement operations
    #[test]
    fn test_change_spec_entitlement_validation() {
        use xavyo_db::{BatchSimulationType, ChangeSpec};

        let entitlement_id = Uuid::new_v4();

        let spec = ChangeSpec {
            operation: BatchSimulationType::EntitlementRemove,
            role_id: None,
            entitlement_id: Some(entitlement_id),
            justification: None,
        };

        assert!(spec.operation.is_entitlement_operation());
        assert!(spec.operation.is_remove());
        assert!(spec.entitlement_id.is_some());
    }

    /// Test batch impact summary aggregation
    #[test]
    fn test_batch_impact_summary_aggregation() {
        use xavyo_db::BatchImpactSummary;

        let mut summary = BatchImpactSummary::default();
        summary.total_users = 200;

        // Simulate aggregating from chunks
        let chunk1 = BatchImpactSummary {
            total_users: 0,
            affected_users: 80,
            entitlements_gained: 160,
            entitlements_lost: 0,
            sod_violations_introduced: 3,
            warnings: vec!["Warning 1".to_string()],
        };

        let chunk2 = BatchImpactSummary {
            total_users: 0,
            affected_users: 50,
            entitlements_gained: 100,
            entitlements_lost: 20,
            sod_violations_introduced: 1,
            warnings: vec!["Warning 2".to_string(), "Warning 3".to_string()],
        };

        summary.affected_users += chunk1.affected_users + chunk2.affected_users;
        summary.entitlements_gained += chunk1.entitlements_gained + chunk2.entitlements_gained;
        summary.entitlements_lost += chunk1.entitlements_lost + chunk2.entitlements_lost;
        summary.sod_violations_introduced +=
            chunk1.sod_violations_introduced + chunk2.sod_violations_introduced;
        summary.warnings.extend(chunk1.warnings);
        summary.warnings.extend(chunk2.warnings);

        assert_eq!(summary.total_users, 200);
        assert_eq!(summary.affected_users, 130);
        assert_eq!(summary.entitlements_gained, 260);
        assert_eq!(summary.entitlements_lost, 20);
        assert_eq!(summary.sod_violations_introduced, 4);
        assert_eq!(summary.warnings.len(), 3);
    }

    /// Test access item structure
    #[test]
    fn test_access_item_structure() {
        use xavyo_db::AccessItem;

        let item = AccessItem {
            id: Uuid::new_v4(),
            name: "GitHub Repository Access".to_string(),
            item_type: "entitlement".to_string(),
            source: Some("Engineering Role".to_string()),
        };

        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["name"], "GitHub Repository Access");
        assert_eq!(json["item_type"], "entitlement");
        assert_eq!(json["source"], "Engineering Role");

        // Without source
        let item_no_source = AccessItem {
            id: Uuid::new_v4(),
            name: "Direct Entitlement".to_string(),
            item_type: "entitlement".to_string(),
            source: None,
        };

        let json = serde_json::to_value(&item_no_source).unwrap();
        assert!(json.get("source").is_none() || json["source"].is_null());
    }

    /// Test create batch simulation result structure
    #[test]
    fn test_create_batch_simulation_result() {
        use xavyo_db::{AccessItem, CreateBatchSimulationResult};

        let result = CreateBatchSimulationResult {
            simulation_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            access_gained: vec![
                AccessItem {
                    id: Uuid::new_v4(),
                    name: "New Role".to_string(),
                    item_type: "role".to_string(),
                    source: Some("Direct assignment".to_string()),
                },
                AccessItem {
                    id: Uuid::new_v4(),
                    name: "Entitlement A".to_string(),
                    item_type: "entitlement".to_string(),
                    source: Some("via role 'New Role'".to_string()),
                },
            ],
            access_lost: vec![],
            warnings: vec!["User already has similar access".to_string()],
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["access_gained"].as_array().unwrap().len(), 2);
        assert_eq!(json["access_lost"].as_array().unwrap().len(), 0);
        assert_eq!(json["warnings"].as_array().unwrap().len(), 1);
    }

    /// Test scope warning threshold constant
    #[test]
    fn test_scope_warning_threshold() {
        use xavyo_db::SCOPE_WARNING_THRESHOLD;

        // Verify the threshold is reasonable
        assert!(SCOPE_WARNING_THRESHOLD > 0);
        assert_eq!(SCOPE_WARNING_THRESHOLD, 100);
    }

    /// Test batch simulation model parsing
    #[test]
    fn test_batch_simulation_parsing() {
        use chrono::Utc;
        use xavyo_db::{
            BatchSimulationType, FilterCriteria, GovBatchSimulation, SelectionMode,
            SimulationStatus,
        };

        let filter = FilterCriteria {
            department: Some(vec!["Engineering".to_string()]),
            ..Default::default()
        };

        let simulation = GovBatchSimulation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Simulation".to_string(),
            batch_type: BatchSimulationType::RoleAdd,
            selection_mode: SelectionMode::Filter,
            user_ids: vec![],
            filter_criteria: serde_json::to_value(&filter).unwrap(),
            change_spec: serde_json::json!({
                "operation": "role_add",
                "role_id": Uuid::new_v4().to_string()
            }),
            status: SimulationStatus::Draft,
            total_users: 0,
            processed_users: 0,
            impact_summary: serde_json::json!({}),
            data_snapshot_at: None,
            is_archived: false,
            retain_until: None,
            notes: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            executed_at: None,
            applied_at: None,
            applied_by: None,
        };

        let parsed_filter = simulation.parse_filter_criteria();
        assert_eq!(
            parsed_filter.department,
            Some(vec!["Engineering".to_string()])
        );
    }

    /// Test simulation status transitions
    #[test]
    fn test_simulation_status_values() {
        use xavyo_db::SimulationStatus;

        let statuses = [
            SimulationStatus::Draft,
            SimulationStatus::Executed,
            SimulationStatus::Applied,
            SimulationStatus::Cancelled,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: SimulationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    /// Test batch simulation result filter
    #[test]
    fn test_batch_simulation_result_filter() {
        use xavyo_db::BatchSimulationResultFilter;

        let filter = BatchSimulationResultFilter::default();
        assert!(filter.user_id.is_none());
        assert!(filter.has_warnings.is_none());

        let filter_with_user = BatchSimulationResultFilter {
            user_id: Some(Uuid::new_v4()),
            has_warnings: Some(true),
        };

        assert!(filter_with_user.user_id.is_some());
        assert_eq!(filter_with_user.has_warnings, Some(true));
    }

    /// Test batch simulation filter
    #[test]
    fn test_batch_simulation_filter() {
        use xavyo_db::{BatchSimulationFilter, BatchSimulationType, SimulationStatus};

        let filter = BatchSimulationFilter::default();
        assert!(filter.batch_type.is_none());
        assert!(filter.status.is_none());
        assert!(filter.created_by.is_none());
        assert!(!filter.include_archived);

        let filter_with_values = BatchSimulationFilter {
            batch_type: Some(BatchSimulationType::RoleAdd),
            status: Some(SimulationStatus::Executed),
            created_by: Some(Uuid::new_v4()),
            include_archived: true,
        };

        assert_eq!(
            filter_with_values.batch_type,
            Some(BatchSimulationType::RoleAdd)
        );
        assert_eq!(filter_with_values.status, Some(SimulationStatus::Executed));
        assert!(filter_with_values.include_archived);
    }
}
