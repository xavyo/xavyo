-- Migration 1182: Fix RLS policies to use NULLIF pattern
-- Adds correct tenant_isolation_policy to 150 tables that only have
-- the incorrect current_setting('app.current_tenant', true)::uuid pattern
-- (which errors on empty string instead of gracefully returning no rows).
--
-- The correct NULLIF pattern converts empty string to NULL, so
-- tenant_id = NULL evaluates to false (SQL three-valued logic),
-- silently returning no rows instead of throwing a runtime error.

BEGIN;

DROP POLICY IF EXISTS tenant_isolation_policy ON ai_agent_approval_requests;
CREATE POLICY tenant_isolation_policy ON ai_agent_approval_requests FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON ai_agent_audit_events;
CREATE POLICY tenant_isolation_policy ON ai_agent_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON ai_agent_tool_permissions;
CREATE POLICY tenant_isolation_policy ON ai_agent_tool_permissions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON ai_agents;
CREATE POLICY tenant_isolation_policy ON ai_agents FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON ai_tools;
CREATE POLICY tenant_isolation_policy ON ai_tools FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON anomaly_baselines;
CREATE POLICY tenant_isolation_policy ON anomaly_baselines FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON anomaly_thresholds;
CREATE POLICY tenant_isolation_policy ON anomaly_thresholds FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON api_keys;
CREATE POLICY tenant_isolation_policy ON api_keys FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON archetype_policy_bindings;
CREATE POLICY tenant_isolation_policy ON archetype_policy_bindings FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON attribute_mappings;
CREATE POLICY tenant_isolation_policy ON attribute_mappings FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON authorization_policies;
CREATE POLICY tenant_isolation_policy ON authorization_policies FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON conflict_records;
CREATE POLICY tenant_isolation_policy ON conflict_records FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON connector_configurations;
CREATE POLICY tenant_isolation_policy ON connector_configurations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON connector_health;
CREATE POLICY tenant_isolation_policy ON connector_health FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON connector_schema_versions;
CREATE POLICY tenant_isolation_policy ON connector_schema_versions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON connector_schemas;
CREATE POLICY tenant_isolation_policy ON connector_schemas FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON detected_anomalies;
CREATE POLICY tenant_isolation_policy ON detected_anomalies FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON device_code_confirmations;
CREATE POLICY tenant_isolation_policy ON device_code_confirmations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON device_codes;
CREATE POLICY tenant_isolation_policy ON device_codes FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON device_mfa_sessions;
CREATE POLICY tenant_isolation_policy ON device_mfa_sessions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON entitlement_action_mappings;
CREATE POLICY tenant_isolation_policy ON entitlement_action_mappings FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_access_patterns;
CREATE POLICY tenant_isolation_policy ON gov_access_patterns FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_access_snapshots;
CREATE POLICY tenant_isolation_policy ON gov_access_snapshots FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_applications;
CREATE POLICY tenant_isolation_policy ON gov_applications FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_approval_decisions;
CREATE POLICY tenant_isolation_policy ON gov_approval_decisions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_approval_delegations;
CREATE POLICY tenant_isolation_policy ON gov_approval_delegations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_approval_workflows;
CREATE POLICY tenant_isolation_policy ON gov_approval_workflows FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_archived_identities;
CREATE POLICY tenant_isolation_policy ON gov_archived_identities FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_birthright_policies;
CREATE POLICY tenant_isolation_policy ON gov_birthright_policies FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_bulk_actions;
CREATE POLICY tenant_isolation_policy ON gov_bulk_actions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_bulk_state_operations;
CREATE POLICY tenant_isolation_policy ON gov_bulk_state_operations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_certification_campaigns;
CREATE POLICY tenant_isolation_policy ON gov_certification_campaigns FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_certification_items;
CREATE POLICY tenant_isolation_policy ON gov_certification_items FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_connector_reconciliation_runs;
CREATE POLICY tenant_isolation_policy ON gov_connector_reconciliation_runs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_consolidation_suggestions;
CREATE POLICY tenant_isolation_policy ON gov_consolidation_suggestions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_correlation_audit_events;
CREATE POLICY tenant_isolation_policy ON gov_correlation_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_correlation_cases;
CREATE POLICY tenant_isolation_policy ON gov_correlation_cases FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_correlation_rules;
CREATE POLICY tenant_isolation_policy ON gov_correlation_rules FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_correlation_thresholds;
CREATE POLICY tenant_isolation_policy ON gov_correlation_thresholds FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_detection_rules;
CREATE POLICY tenant_isolation_policy ON gov_detection_rules FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_duplicate_candidates;
CREATE POLICY tenant_isolation_policy ON gov_duplicate_candidates FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_excessive_privileges;
CREATE POLICY tenant_isolation_policy ON gov_excessive_privileges FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_external_tickets;
CREATE POLICY tenant_isolation_policy ON gov_external_tickets FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_generated_reports;
CREATE POLICY tenant_isolation_policy ON gov_generated_reports FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_inbound_changes;
CREATE POLICY tenant_isolation_policy ON gov_inbound_changes FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_lifecycle_actions;
CREATE POLICY tenant_isolation_policy ON gov_lifecycle_actions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_lifecycle_configs;
CREATE POLICY tenant_isolation_policy ON gov_lifecycle_configs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_lifecycle_events;
CREATE POLICY tenant_isolation_policy ON gov_lifecycle_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_lifecycle_failed_operations;
CREATE POLICY tenant_isolation_policy ON gov_lifecycle_failed_operations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_lifecycle_states;
CREATE POLICY tenant_isolation_policy ON gov_lifecycle_states FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_lifecycle_transitions;
CREATE POLICY tenant_isolation_policy ON gov_lifecycle_transitions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_manual_provisioning_tasks;
CREATE POLICY tenant_isolation_policy ON gov_manual_provisioning_tasks FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_manual_task_audit_events;
CREATE POLICY tenant_isolation_policy ON gov_manual_task_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_merge_audits;
CREATE POLICY tenant_isolation_policy ON gov_merge_audits FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_merge_operations;
CREATE POLICY tenant_isolation_policy ON gov_merge_operations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_micro_cert_events;
CREATE POLICY tenant_isolation_policy ON gov_micro_cert_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_micro_cert_triggers;
CREATE POLICY tenant_isolation_policy ON gov_micro_cert_triggers FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_micro_certifications;
CREATE POLICY tenant_isolation_policy ON gov_micro_certifications FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_nhi_audit_events;
CREATE POLICY tenant_isolation_policy ON gov_nhi_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_nhi_credentials;
CREATE POLICY tenant_isolation_policy ON gov_nhi_credentials FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_nhi_requests;
CREATE POLICY tenant_isolation_policy ON gov_nhi_requests FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_nhi_risk_scores;
CREATE POLICY tenant_isolation_policy ON gov_nhi_risk_scores FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_nhi_usage_events;
CREATE POLICY tenant_isolation_policy ON gov_nhi_usage_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_orphan_detections;
CREATE POLICY tenant_isolation_policy ON gov_orphan_detections FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_outlier_alerts;
CREATE POLICY tenant_isolation_policy ON gov_outlier_alerts FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_outlier_analyses;
CREATE POLICY tenant_isolation_policy ON gov_outlier_analyses FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_outlier_configurations;
CREATE POLICY tenant_isolation_policy ON gov_outlier_configurations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_outlier_dispositions;
CREATE POLICY tenant_isolation_policy ON gov_outlier_dispositions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_outlier_results;
CREATE POLICY tenant_isolation_policy ON gov_outlier_results FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_peer_group_members;
CREATE POLICY tenant_isolation_policy ON gov_peer_group_members FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_peer_groups;
CREATE POLICY tenant_isolation_policy ON gov_peer_groups FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_persona_archetypes;
CREATE POLICY tenant_isolation_policy ON gov_persona_archetypes FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_persona_audit_events;
CREATE POLICY tenant_isolation_policy ON gov_persona_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_persona_links;
CREATE POLICY tenant_isolation_policy ON gov_persona_links FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_persona_sessions;
CREATE POLICY tenant_isolation_policy ON gov_persona_sessions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_personas;
CREATE POLICY tenant_isolation_policy ON gov_personas FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_provisioning_scripts;
CREATE POLICY tenant_isolation_policy ON gov_provisioning_scripts FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_reconciliation_actions;
CREATE POLICY tenant_isolation_policy ON gov_reconciliation_actions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_reconciliation_discrepancies;
CREATE POLICY tenant_isolation_policy ON gov_reconciliation_discrepancies FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_reconciliation_runs;
CREATE POLICY tenant_isolation_policy ON gov_reconciliation_runs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_reconciliation_schedules;
CREATE POLICY tenant_isolation_policy ON gov_reconciliation_schedules FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_remediation_logs;
CREATE POLICY tenant_isolation_policy ON gov_remediation_logs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_report_schedules;
CREATE POLICY tenant_isolation_policy ON gov_report_schedules FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_report_templates;
CREATE POLICY tenant_isolation_policy ON gov_report_templates FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_risk_alerts;
CREATE POLICY tenant_isolation_policy ON gov_risk_alerts FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_risk_enforcement_policies;
CREATE POLICY tenant_isolation_policy ON gov_risk_enforcement_policies FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_risk_events;
CREATE POLICY tenant_isolation_policy ON gov_risk_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_risk_factors;
CREATE POLICY tenant_isolation_policy ON gov_risk_factors FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_risk_score_history;
CREATE POLICY tenant_isolation_policy ON gov_risk_score_history FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_risk_scores;
CREATE POLICY tenant_isolation_policy ON gov_risk_scores FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_risk_thresholds;
CREATE POLICY tenant_isolation_policy ON gov_risk_thresholds FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_candidates;
CREATE POLICY tenant_isolation_policy ON gov_role_candidates FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_entitlements;
CREATE POLICY tenant_isolation_policy ON gov_role_entitlements FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_metrics;
CREATE POLICY tenant_isolation_policy ON gov_role_metrics FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_mining_jobs;
CREATE POLICY tenant_isolation_policy ON gov_role_mining_jobs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_simulations;
CREATE POLICY tenant_isolation_policy ON gov_role_simulations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_scheduled_transitions;
CREATE POLICY tenant_isolation_policy ON gov_scheduled_transitions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_script_audit_events;
CREATE POLICY tenant_isolation_policy ON gov_script_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_script_execution_logs;
CREATE POLICY tenant_isolation_policy ON gov_script_execution_logs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_script_hook_bindings;
CREATE POLICY tenant_isolation_policy ON gov_script_hook_bindings FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_script_templates;
CREATE POLICY tenant_isolation_policy ON gov_script_templates FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_script_versions;
CREATE POLICY tenant_isolation_policy ON gov_script_versions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_service_accounts;
CREATE POLICY tenant_isolation_policy ON gov_service_accounts FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_shadows;
CREATE POLICY tenant_isolation_policy ON gov_shadows FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sla_policies;
CREATE POLICY tenant_isolation_policy ON gov_sla_policies FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sod_exemptions;
CREATE POLICY tenant_isolation_policy ON gov_sod_exemptions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sod_rules;
CREATE POLICY tenant_isolation_policy ON gov_sod_rules FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sod_violations;
CREATE POLICY tenant_isolation_policy ON gov_sod_violations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_state_transition_audit;
CREATE POLICY tenant_isolation_policy ON gov_state_transition_audit FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_state_transition_requests;
CREATE POLICY tenant_isolation_policy ON gov_state_transition_requests FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sync_configurations;
CREATE POLICY tenant_isolation_policy ON gov_sync_configurations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sync_conflicts;
CREATE POLICY tenant_isolation_policy ON gov_sync_conflicts FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sync_status;
CREATE POLICY tenant_isolation_policy ON gov_sync_status FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_sync_tokens;
CREATE POLICY tenant_isolation_policy ON gov_sync_tokens FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON gov_ticketing_configurations;
CREATE POLICY tenant_isolation_policy ON gov_ticketing_configurations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON idempotent_requests;
CREATE POLICY tenant_isolation_policy ON idempotent_requests FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON identity_archetypes;
CREATE POLICY tenant_isolation_policy ON identity_archetypes FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON known_user_ips;
CREATE POLICY tenant_isolation_policy ON known_user_ips FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON operation_attempts;
CREATE POLICY tenant_isolation_policy ON operation_attempts FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON operation_logs;
CREATE POLICY tenant_isolation_policy ON operation_logs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON poa_assumed_sessions;
CREATE POLICY tenant_isolation_policy ON poa_assumed_sessions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON poa_audit_events;
CREATE POLICY tenant_isolation_policy ON poa_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON policy_audit_events;
CREATE POLICY tenant_isolation_policy ON policy_audit_events FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON policy_conditions;
CREATE POLICY tenant_isolation_policy ON policy_conditions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON policy_obligations;
CREATE POLICY tenant_isolation_policy ON policy_obligations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON policy_versions;
CREATE POLICY tenant_isolation_policy ON policy_versions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON power_of_attorneys;
CREATE POLICY tenant_isolation_policy ON power_of_attorneys FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON provisioning_operations;
CREATE POLICY tenant_isolation_policy ON provisioning_operations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON revoked_tokens;
CREATE POLICY tenant_isolation_policy ON revoked_tokens FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON saml_authn_request_sessions;
CREATE POLICY tenant_isolation_policy ON saml_authn_request_sessions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON schema_refresh_schedules;
CREATE POLICY tenant_isolation_policy ON schema_refresh_schedules FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON scim_provisioning_log;
CREATE POLICY tenant_isolation_policy ON scim_provisioning_log FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON scim_provisioning_states;
CREATE POLICY tenant_isolation_policy ON scim_provisioning_states FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON scim_sync_runs;
CREATE POLICY tenant_isolation_policy ON scim_sync_runs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON scim_target_attribute_mappings;
CREATE POLICY tenant_isolation_policy ON scim_target_attribute_mappings FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON scim_targets;
CREATE POLICY tenant_isolation_policy ON scim_targets FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON signing_keys;
CREATE POLICY tenant_isolation_policy ON signing_keys FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_active_users;
CREATE POLICY tenant_isolation_policy ON tenant_active_users FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_attribute_definitions;
CREATE POLICY tenant_isolation_policy ON tenant_attribute_definitions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_mfa_policies;
CREATE POLICY tenant_isolation_policy ON tenant_mfa_policies FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_usage_metrics;
CREATE POLICY tenant_isolation_policy ON tenant_usage_metrics FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON unified_nhi_certification_campaigns;
CREATE POLICY tenant_isolation_policy ON unified_nhi_certification_campaigns FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON unified_nhi_certification_items;
CREATE POLICY tenant_isolation_policy ON unified_nhi_certification_items FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON user_import_errors;
CREATE POLICY tenant_isolation_policy ON user_import_errors FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON user_import_jobs;
CREATE POLICY tenant_isolation_policy ON user_import_jobs FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON user_invitations;
CREATE POLICY tenant_isolation_policy ON user_invitations FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON webhook_circuit_breaker_state;
CREATE POLICY tenant_isolation_policy ON webhook_circuit_breaker_state FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON webhook_deliveries;
CREATE POLICY tenant_isolation_policy ON webhook_deliveries FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON webhook_dlq;
CREATE POLICY tenant_isolation_policy ON webhook_dlq FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON webhook_subscriptions;
CREATE POLICY tenant_isolation_policy ON webhook_subscriptions FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

COMMIT;
