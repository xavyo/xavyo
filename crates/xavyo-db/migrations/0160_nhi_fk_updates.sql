-- Migration 1196: Update FK references on dependent tables to point to nhi_identities
-- Part of 201-tool-nhi-promotion: all dependent tables now reference the unified table.

-- ============================================================================
-- Tables with FK to ai_agents(id) — update to nhi_identities(id)
-- ============================================================================

-- a2a_tasks: source_agent_id, target_agent_id
ALTER TABLE a2a_tasks DROP CONSTRAINT IF EXISTS a2a_tasks_source_agent_id_fkey;
ALTER TABLE a2a_tasks DROP CONSTRAINT IF EXISTS a2a_tasks_target_agent_id_fkey;
ALTER TABLE a2a_tasks ADD CONSTRAINT a2a_tasks_source_agent_id_fkey
    FOREIGN KEY (source_agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;
ALTER TABLE a2a_tasks ADD CONSTRAINT a2a_tasks_target_agent_id_fkey
    FOREIGN KEY (target_agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- anomaly_baselines: agent_id
ALTER TABLE anomaly_baselines DROP CONSTRAINT IF EXISTS anomaly_baselines_agent_id_fkey;
ALTER TABLE anomaly_baselines ADD CONSTRAINT anomaly_baselines_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- detected_anomalies: agent_id
ALTER TABLE detected_anomalies DROP CONSTRAINT IF EXISTS detected_anomalies_agent_id_fkey;
ALTER TABLE detected_anomalies ADD CONSTRAINT detected_anomalies_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- anomaly_thresholds: agent_id
ALTER TABLE anomaly_thresholds DROP CONSTRAINT IF EXISTS anomaly_thresholds_agent_id_fkey;
ALTER TABLE anomaly_thresholds ADD CONSTRAINT anomaly_thresholds_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- agent_secret_permissions: agent_id
ALTER TABLE agent_secret_permissions DROP CONSTRAINT IF EXISTS agent_secret_permissions_agent_id_fkey;
ALTER TABLE agent_secret_permissions ADD CONSTRAINT agent_secret_permissions_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- dynamic_credentials: agent_id
ALTER TABLE dynamic_credentials DROP CONSTRAINT IF EXISTS dynamic_credentials_agent_id_fkey;
ALTER TABLE dynamic_credentials ADD CONSTRAINT dynamic_credentials_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- identity_credential_requests: agent_id
ALTER TABLE identity_credential_requests DROP CONSTRAINT IF EXISTS identity_credential_requests_agent_id_fkey;
ALTER TABLE identity_credential_requests ADD CONSTRAINT identity_credential_requests_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- agent_certificates: agent_id
ALTER TABLE agent_certificates DROP CONSTRAINT IF EXISTS agent_certificates_agent_id_fkey;
ALTER TABLE agent_certificates ADD CONSTRAINT agent_certificates_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- ai_agent_audit_events: agent_id, tool_id
ALTER TABLE ai_agent_audit_events DROP CONSTRAINT IF EXISTS ai_agent_audit_events_agent_id_fkey;
ALTER TABLE ai_agent_audit_events DROP CONSTRAINT IF EXISTS ai_agent_audit_events_tool_id_fkey;
ALTER TABLE ai_agent_audit_events ADD CONSTRAINT ai_agent_audit_events_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;
ALTER TABLE ai_agent_audit_events ADD CONSTRAINT ai_agent_audit_events_tool_id_fkey
    FOREIGN KEY (tool_id) REFERENCES nhi_identities(id) ON DELETE SET NULL;

-- ai_agent_approval_requests: agent_id, tool_id
ALTER TABLE ai_agent_approval_requests DROP CONSTRAINT IF EXISTS ai_agent_approval_requests_agent_id_fkey;
ALTER TABLE ai_agent_approval_requests DROP CONSTRAINT IF EXISTS ai_agent_approval_requests_tool_id_fkey;
ALTER TABLE ai_agent_approval_requests ADD CONSTRAINT ai_agent_approval_requests_agent_id_fkey
    FOREIGN KEY (agent_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;
ALTER TABLE ai_agent_approval_requests ADD CONSTRAINT ai_agent_approval_requests_tool_id_fkey
    FOREIGN KEY (tool_id) REFERENCES nhi_identities(id) ON DELETE SET NULL;

-- ============================================================================
-- Tables with FK to gov_service_accounts(id) — update to nhi_identities(id)
-- ============================================================================

-- gov_nhi_risk_scores: nhi_id
ALTER TABLE gov_nhi_risk_scores DROP CONSTRAINT IF EXISTS gov_nhi_risk_scores_nhi_id_fkey;
ALTER TABLE gov_nhi_risk_scores ADD CONSTRAINT gov_nhi_risk_scores_nhi_id_fkey
    FOREIGN KEY (nhi_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- gov_nhi_requests: created_nhi_id
ALTER TABLE gov_nhi_requests DROP CONSTRAINT IF EXISTS gov_nhi_requests_created_nhi_id_fkey;
ALTER TABLE gov_nhi_requests ADD CONSTRAINT gov_nhi_requests_created_nhi_id_fkey
    FOREIGN KEY (created_nhi_id) REFERENCES nhi_identities(id) ON DELETE SET NULL;

-- ============================================================================
-- Tables with polymorphic FK (no constraint before) — add proper FK
-- ============================================================================

-- gov_nhi_audit_events: nhi_id (was validated by trigger, now proper FK)
ALTER TABLE gov_nhi_audit_events DROP CONSTRAINT IF EXISTS gov_nhi_audit_events_nhi_id_fkey;
ALTER TABLE gov_nhi_audit_events ADD CONSTRAINT gov_nhi_audit_events_nhi_id_fkey
    FOREIGN KEY (nhi_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- gov_nhi_usage_events: nhi_id (was validated by trigger, now proper FK)
ALTER TABLE gov_nhi_usage_events DROP CONSTRAINT IF EXISTS gov_nhi_usage_events_nhi_id_fkey;
ALTER TABLE gov_nhi_usage_events ADD CONSTRAINT gov_nhi_usage_events_nhi_id_fkey
    FOREIGN KEY (nhi_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- unified_nhi_certification_items: nhi_id (was polymorphic, now proper FK)
ALTER TABLE unified_nhi_certification_items DROP CONSTRAINT IF EXISTS unified_nhi_certification_items_nhi_id_fkey;
ALTER TABLE unified_nhi_certification_items ADD CONSTRAINT unified_nhi_certification_items_nhi_id_fkey
    FOREIGN KEY (nhi_id) REFERENCES nhi_identities(id) ON DELETE CASCADE;

-- ============================================================================
-- admin_audit_log: Add NHI resource types to CHECK constraint (R-010)
-- ============================================================================

ALTER TABLE admin_audit_log DROP CONSTRAINT IF EXISTS chk_audit_resource_type;
ALTER TABLE admin_audit_log ADD CONSTRAINT chk_audit_resource_type CHECK (
    resource_type IN (
        'user', 'template', 'assignment', 'permission', 'tenant',
        'api_key', 'oauth_client', 'mfa_policy', 'session_policy', 'password_policy',
        'tenant_settings', 'tenant_plan', 'admin_invitation',
        'gov_role', 'gov_role_inheritance_block', 'gov_role_entitlement',
        -- NHI resource types (201-tool-nhi-promotion)
        'nhi_identity', 'nhi_tool', 'nhi_agent', 'nhi_service_account',
        'nhi_credential', 'nhi_certification', 'nhi_tool_permission'
    )
);
