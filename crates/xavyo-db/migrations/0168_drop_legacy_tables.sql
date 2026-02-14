-- Feature 205: Drop legacy AI agent tables after protocol migration to NHI.
-- These tables are superseded by nhi_identities, nhi_agents, nhi_tools, nhi_tool_permissions.

-- Drop in FK-dependency order (children first)
DROP TABLE IF EXISTS ai_agent_tool_permissions CASCADE;
DROP TABLE IF EXISTS ai_agent_audit_events CASCADE;
DROP TABLE IF EXISTS ai_agent_approval_requests CASCADE;

-- Drop parent tables
DROP TABLE IF EXISTS ai_tools CASCADE;
DROP TABLE IF EXISTS ai_agents CASCADE;

-- Drop unmounted feature tables that were never used in production
DROP TABLE IF EXISTS anomaly_baselines CASCADE;
DROP TABLE IF EXISTS anomaly_thresholds CASCADE;
DROP TABLE IF EXISTS detected_anomalies CASCADE;
DROP TABLE IF EXISTS workload_identity_federations CASCADE;
DROP TABLE IF EXISTS agent_pki_certificates CASCADE;
