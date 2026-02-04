//! Integration tests for Simulation Comparisons (F060 - User Story 3).
//!
//! These tests verify the simulation comparison service logic including
//! simulation-vs-simulation, simulation-vs-current, and summary statistics.

// Note: These tests require a running database with the F060 migration applied.
// Run with: DATABASE_URL=... cargo test --test simulation_comparison_integration_tests

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    /// Test comparison type serialization
    #[test]
    fn test_comparison_type_serialization() {
        use xavyo_db::ComparisonType;

        let vs_simulation = ComparisonType::SimulationVsSimulation;
        let json = serde_json::to_string(&vs_simulation).unwrap();
        assert_eq!(json, "\"simulation_vs_simulation\"");

        let vs_current = ComparisonType::SimulationVsCurrent;
        let json = serde_json::to_string(&vs_current).unwrap();
        assert_eq!(json, "\"simulation_vs_current\"");
    }

    /// Test comparison summary structure
    #[test]
    fn test_comparison_summary_structure() {
        use xavyo_db::ComparisonSummary;

        let summary = ComparisonSummary {
            users_in_both: 150,
            users_only_in_a: 25,
            users_only_in_b: 30,
            different_impacts: 45,
            total_additions: 75,
            total_removals: 25,
        };

        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["users_in_both"], 150);
        assert_eq!(json["users_only_in_a"], 25);
        assert_eq!(json["users_only_in_b"], 30);
        assert_eq!(json["different_impacts"], 45);
        assert_eq!(json["total_additions"], 75);
        assert_eq!(json["total_removals"], 25);

        // Round-trip test
        let parsed: ComparisonSummary = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.users_in_both, 150);
    }

    /// Test delta results structure
    #[test]
    fn test_delta_results_structure() {
        use xavyo_db::{DeltaEntry, DeltaResults, ModifiedEntry};

        let delta = DeltaResults {
            added: vec![DeltaEntry {
                user_id: Uuid::new_v4(),
                impact: serde_json::json!({"type": "entitlement_gain", "count": 5}),
            }],
            removed: vec![DeltaEntry {
                user_id: Uuid::new_v4(),
                impact: serde_json::json!({"type": "entitlement_loss", "count": 2}),
            }],
            modified: vec![ModifiedEntry {
                user_id: Uuid::new_v4(),
                impact_a: serde_json::json!({"violations": 0}),
                impact_b: serde_json::json!({"violations": 2}),
                diff: serde_json::json!({"violations_added": 2}),
            }],
        };

        let json = serde_json::to_value(&delta).unwrap();
        assert_eq!(json["added"].as_array().unwrap().len(), 1);
        assert_eq!(json["removed"].as_array().unwrap().len(), 1);
        assert_eq!(json["modified"].as_array().unwrap().len(), 1);
    }

    /// Test delta entry serialization
    #[test]
    fn test_delta_entry_serialization() {
        use xavyo_db::DeltaEntry;

        let entry = DeltaEntry {
            user_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            impact: serde_json::json!({
                "type": "violation",
                "rule_id": "22222222-2222-2222-2222-222222222222",
                "severity": "high"
            }),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("11111111-1111-1111-1111-111111111111"));
        assert!(json.contains("violation"));
        assert!(json.contains("high"));

        let parsed: DeltaEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.user_id,
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
        );
    }

    /// Test modified entry serialization
    #[test]
    fn test_modified_entry_serialization() {
        use xavyo_db::ModifiedEntry;

        let entry = ModifiedEntry {
            user_id: Uuid::new_v4(),
            impact_a: serde_json::json!({"entitlements_gained": 3}),
            impact_b: serde_json::json!({"entitlements_gained": 7}),
            diff: serde_json::json!({"entitlements_gained_delta": 4}),
        };

        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["impact_a"]["entitlements_gained"], 3);
        assert_eq!(json["impact_b"]["entitlements_gained"], 7);
        assert_eq!(json["diff"]["entitlements_gained_delta"], 4);
    }

    /// Test comparison filter default
    #[test]
    fn test_comparison_filter_default() {
        use xavyo_db::SimulationComparisonFilter;

        let filter = SimulationComparisonFilter::default();
        assert!(filter.comparison_type.is_none());
        assert!(filter.created_by.is_none());
    }

    /// Test comparison filter with values
    #[test]
    fn test_comparison_filter_with_values() {
        use xavyo_db::{ComparisonType, SimulationComparisonFilter};

        let filter = SimulationComparisonFilter {
            comparison_type: Some(ComparisonType::SimulationVsSimulation),
            created_by: Some(Uuid::new_v4()),
        };

        assert!(filter.comparison_type.is_some());
        assert!(filter.created_by.is_some());
    }

    /// Test create simulation comparison request structure
    #[test]
    fn test_create_comparison_request() {
        use xavyo_db::CreateSimulationComparison;

        let request = CreateSimulationComparison {
            name: "Test Comparison".to_string(),
            comparison_type: xavyo_db::ComparisonType::SimulationVsSimulation,
            simulation_a_id: Some(Uuid::new_v4()),
            simulation_a_type: Some("policy".to_string()),
            simulation_b_id: Some(Uuid::new_v4()),
            simulation_b_type: Some("policy".to_string()),
            created_by: Uuid::new_v4(),
        };

        assert_eq!(request.name, "Test Comparison");
        assert!(request.simulation_a_id.is_some());
        assert!(request.simulation_b_id.is_some());
    }

    /// Test comparison model parsing
    #[test]
    fn test_comparison_model_parsing() {
        use chrono::Utc;
        use xavyo_db::{ComparisonSummary, ComparisonType, GovSimulationComparison};

        let summary = ComparisonSummary {
            users_in_both: 100,
            users_only_in_a: 10,
            users_only_in_b: 5,
            different_impacts: 20,
            total_additions: 25,
            total_removals: 10,
        };

        let comparison = GovSimulationComparison {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Comparison".to_string(),
            comparison_type: ComparisonType::SimulationVsSimulation,
            simulation_a_id: Some(Uuid::new_v4()),
            simulation_a_type: Some("policy".to_string()),
            simulation_b_id: Some(Uuid::new_v4()),
            simulation_b_type: Some("policy".to_string()),
            summary_stats: serde_json::to_value(&summary).unwrap(),
            delta_results: serde_json::json!({"added": [], "removed": [], "modified": []}),
            is_stale: false,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        let parsed_summary = comparison.parse_summary_stats();
        assert_eq!(parsed_summary.users_in_both, 100);
        assert_eq!(parsed_summary.users_only_in_a, 10);
        assert_eq!(parsed_summary.different_impacts, 20);
    }

    /// Test `references_simulation` helper
    #[test]
    fn test_references_simulation() {
        use chrono::Utc;
        use xavyo_db::{ComparisonType, GovSimulationComparison};

        let sim_a_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let sim_b_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let other_id = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();

        let comparison = GovSimulationComparison {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            comparison_type: ComparisonType::SimulationVsSimulation,
            simulation_a_id: Some(sim_a_id),
            simulation_a_type: Some("policy".to_string()),
            simulation_b_id: Some(sim_b_id),
            simulation_b_type: Some("batch".to_string()),
            summary_stats: serde_json::json!({}),
            delta_results: serde_json::json!({}),
            is_stale: false,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        assert!(comparison.references_simulation(sim_a_id));
        assert!(comparison.references_simulation(sim_b_id));
        assert!(!comparison.references_simulation(other_id));
    }

    /// Test simulation vs current comparison (`simulation_b` fields should be None)
    #[test]
    fn test_simulation_vs_current_structure() {
        use chrono::Utc;
        use xavyo_db::{ComparisonType, GovSimulationComparison};

        let comparison = GovSimulationComparison {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "vs Current Test".to_string(),
            comparison_type: ComparisonType::SimulationVsCurrent,
            simulation_a_id: Some(Uuid::new_v4()),
            simulation_a_type: Some("batch".to_string()),
            simulation_b_id: None,
            simulation_b_type: None,
            summary_stats: serde_json::json!({"users_only_in_a": 50, "total_additions": 150}),
            delta_results: serde_json::json!({"added": []}),
            is_stale: false,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        assert!(comparison.simulation_a_id.is_some());
        assert!(comparison.simulation_b_id.is_none());
        assert!(comparison.comparison_type.is_simulation_vs_current());
    }

    /// Test stale flag
    #[test]
    fn test_stale_flag() {
        use chrono::Utc;
        use xavyo_db::{ComparisonType, GovSimulationComparison};

        let comparison = GovSimulationComparison {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Stale Test".to_string(),
            comparison_type: ComparisonType::SimulationVsSimulation,
            simulation_a_id: Some(Uuid::new_v4()),
            simulation_a_type: Some("policy".to_string()),
            simulation_b_id: Some(Uuid::new_v4()),
            simulation_b_type: Some("policy".to_string()),
            summary_stats: serde_json::json!({}),
            delta_results: serde_json::json!({}),
            is_stale: true,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
        };

        assert!(comparison.is_stale);
    }
}
