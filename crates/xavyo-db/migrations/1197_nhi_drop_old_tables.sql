-- Migration 1197: Drop old NHI tables replaced by unified model
-- Order: drop dependent tables first, then base tables, then views/functions.
-- CASCADE ensures any remaining dependent objects (triggers, policies) are dropped.

-- 1. Drop ai_agent_tool_permissions (depends on ai_agents and ai_tools)
DROP TABLE IF EXISTS ai_agent_tool_permissions CASCADE;

-- 2. Drop gov_nhi_credentials (depends on gov_service_accounts / ai_agents via trigger)
DROP TABLE IF EXISTS gov_nhi_credentials CASCADE;

-- 3. Drop ai_tools (leaf table after permissions dropped)
DROP TABLE IF EXISTS ai_tools CASCADE;

-- 4. Drop ai_agents (leaf table after permissions, audit events, etc. FK-updated)
DROP TABLE IF EXISTS ai_agents CASCADE;

-- 5. Drop gov_service_accounts (leaf table after credentials, risk scores FK-updated)
DROP TABLE IF EXISTS gov_service_accounts CASCADE;

-- 6. Drop the unified view (no longer needed — nhi_identities IS the unified table)
DROP VIEW IF EXISTS v_non_human_identities;

-- 7. Drop the polymorphic validation function and trigger (R-003)
DROP FUNCTION IF EXISTS validate_nhi_credential_reference() CASCADE;

-- 8. Drop old enum types that are no longer needed (R-009)
-- gov_service_account_status is replaced by lifecycle_state varchar on nhi_identities
DROP TYPE IF EXISTS gov_service_account_status CASCADE;
