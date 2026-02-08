-- Migration 1195: Data migration from old tables to unified NHI model
-- Preserves UUIDs (R-002) so dependent FKs only need target changes, not data updates.
-- Order: base table first (nhi_identities), then extension tables, then credentials/permissions.

-- ============================================================================
-- 1. Migrate ai_agents → nhi_identities + nhi_agents
-- ============================================================================

-- ai_agents columns: id, tenant_id, name, description, agent_type, owner_id,
--   team_id, backup_owner_id, model_provider, model_name, model_version,
--   agent_card_url, agent_card_signature, status, risk_level,
--   max_token_lifetime_secs, requires_human_approval, created_at, updated_at,
--   last_activity_at, expires_at, inactivity_threshold_days,
--   grace_period_ends_at, suspension_reason, rotation_interval_days,
--   last_rotation_at, risk_score, next_certification_at, last_certified_at,
--   last_certified_by

INSERT INTO nhi_identities (
    id, tenant_id, nhi_type, name, description, owner_id, backup_owner_id,
    lifecycle_state, suspension_reason, expires_at, last_activity_at,
    inactivity_threshold_days, grace_period_ends_at, risk_score,
    last_certified_at, next_certification_at, last_certified_by,
    rotation_interval_days, last_rotation_at, created_at, updated_at, created_by
)
SELECT
    a.id,
    a.tenant_id,
    'agent',
    a.name,
    a.description,
    a.owner_id,
    a.backup_owner_id,
    -- Map old status to new lifecycle_state
    CASE a.status
        WHEN 'active' THEN 'active'
        WHEN 'suspended' THEN 'suspended'
        WHEN 'expired' THEN 'inactive'
        ELSE 'active'
    END,
    a.suspension_reason,
    a.expires_at,
    a.last_activity_at,
    a.inactivity_threshold_days,
    a.grace_period_ends_at,
    -- Use existing risk_score if set, otherwise map from risk_level
    COALESCE(a.risk_score, CASE a.risk_level
        WHEN 'critical' THEN 90
        WHEN 'high' THEN 70
        WHEN 'medium' THEN 40
        WHEN 'low' THEN 20
        ELSE 0
    END),
    a.last_certified_at,
    a.next_certification_at,
    a.last_certified_by,
    a.rotation_interval_days,
    a.last_rotation_at,
    a.created_at,
    a.updated_at,
    NULL  -- created_by: ai_agents table has no created_by column
FROM ai_agents a
ON CONFLICT (id) DO NOTHING;

-- Agent extension data (including team_id from old schema)
INSERT INTO nhi_agents (
    nhi_id, agent_type, model_provider, model_name, model_version,
    agent_card_url, agent_card_signature, max_token_lifetime_secs,
    requires_human_approval, team_id
)
SELECT
    a.id,
    a.agent_type,
    a.model_provider,
    a.model_name,
    a.model_version,
    a.agent_card_url,
    a.agent_card_signature,
    a.max_token_lifetime_secs,
    a.requires_human_approval,
    a.team_id
FROM ai_agents a
ON CONFLICT (nhi_id) DO NOTHING;

-- ============================================================================
-- 2. Migrate ai_tools → nhi_identities + nhi_tools
-- ============================================================================

-- ai_tools columns: id, tenant_id, name, description, category, input_schema,
--   output_schema, risk_level, requires_approval, max_calls_per_hour, provider,
--   provider_verified, checksum, status, created_at, updated_at

INSERT INTO nhi_identities (
    id, tenant_id, nhi_type, name, description, owner_id, backup_owner_id,
    lifecycle_state, suspension_reason, expires_at, last_activity_at,
    inactivity_threshold_days, grace_period_ends_at, risk_score,
    last_certified_at, next_certification_at, last_certified_by,
    rotation_interval_days, last_rotation_at, created_at, updated_at, created_by
)
SELECT
    t.id,
    t.tenant_id,
    'tool',
    t.name,
    t.description,
    NULL,  -- tools don't have owner in old schema
    NULL,  -- no backup_owner
    -- Map old status to lifecycle_state
    CASE t.status
        WHEN 'active' THEN 'active'
        WHEN 'inactive' THEN 'inactive'
        WHEN 'deprecated' THEN 'deprecated'
        ELSE 'active'
    END,
    NULL,  -- no suspension_reason
    NULL,  -- no expires_at on tools
    NULL,  -- no last_activity_at on tools
    90,    -- default inactivity threshold
    NULL,  -- no grace period
    -- Map risk_level to numeric score
    CASE t.risk_level
        WHEN 'critical' THEN 90
        WHEN 'high' THEN 70
        WHEN 'medium' THEN 40
        WHEN 'low' THEN 20
        ELSE 0
    END,
    NULL,  -- no certification on tools
    NULL,  -- no next_certification
    NULL,  -- no certified_by
    NULL,  -- no rotation on tools
    NULL,  -- no last_rotation
    t.created_at,
    t.updated_at,
    NULL   -- created_by: ai_tools table has no created_by column
FROM ai_tools t
ON CONFLICT (id) DO NOTHING;

-- Tool extension data
INSERT INTO nhi_tools (
    nhi_id, category, input_schema, output_schema, requires_approval,
    max_calls_per_hour, provider, provider_verified, checksum
)
SELECT
    t.id,
    t.category,
    t.input_schema,
    t.output_schema,
    t.requires_approval,
    t.max_calls_per_hour,
    t.provider,
    t.provider_verified,
    t.checksum
FROM ai_tools t
ON CONFLICT (nhi_id) DO NOTHING;

-- ============================================================================
-- 3. Migrate gov_service_accounts → nhi_identities + nhi_service_accounts
-- ============================================================================

-- gov_service_accounts columns: id, tenant_id, user_id, name, purpose, owner_id,
--   status (enum: active/expired/suspended), expires_at, last_certified_at,
--   certified_by, created_at, updated_at, backup_owner_id, rotation_interval_days,
--   last_rotation_at, last_used_at, inactivity_threshold_days,
--   grace_period_ends_at, suspension_reason, anomaly_threshold,
--   last_anomaly_check_at, anomaly_baseline

INSERT INTO nhi_identities (
    id, tenant_id, nhi_type, name, description, owner_id, backup_owner_id,
    lifecycle_state, suspension_reason, expires_at, last_activity_at,
    inactivity_threshold_days, grace_period_ends_at, risk_score,
    last_certified_at, next_certification_at, last_certified_by,
    rotation_interval_days, last_rotation_at, created_at, updated_at, created_by
)
SELECT
    sa.id,
    sa.tenant_id,
    'service_account',
    sa.name,
    sa.purpose,  -- purpose maps to description
    sa.owner_id,
    sa.backup_owner_id,
    -- Map old status enum to lifecycle_state (unknown states default to inactive for safety)
    CASE sa.status::text
        WHEN 'active' THEN 'active'
        WHEN 'expired' THEN 'inactive'
        WHEN 'suspended' THEN 'suspended'
        ELSE 'inactive'
    END,
    sa.suspension_reason::text,
    sa.expires_at,
    sa.last_used_at,  -- last_used_at maps to last_activity_at
    sa.inactivity_threshold_days,
    sa.grace_period_ends_at,
    0,     -- default risk_score (will be recomputed by risk service)
    sa.last_certified_at,
    NULL,  -- next_certification_at not tracked in old schema
    sa.certified_by,  -- certified_by maps to last_certified_by
    sa.rotation_interval_days,
    sa.last_rotation_at,
    sa.created_at,
    sa.updated_at,
    NULL   -- created_by: gov_service_accounts table has no created_by column
FROM gov_service_accounts sa
ON CONFLICT (id) DO NOTHING;

-- Service account extension data
INSERT INTO nhi_service_accounts (nhi_id, purpose, environment)
SELECT
    sa.id,
    sa.purpose,
    NULL  -- environment not tracked in old schema
FROM gov_service_accounts sa
ON CONFLICT (nhi_id) DO NOTHING;

-- ============================================================================
-- 4. Migrate gov_nhi_credentials → nhi_credentials
-- ============================================================================

-- gov_nhi_credentials columns: id, tenant_id, nhi_id, credential_type (enum),
--   credential_hash, valid_from, valid_until, is_active, rotated_by,
--   created_at, nhi_type (text: service_account/agent)
-- The nhi_type column is dropped — type is now on nhi_identities base table.

INSERT INTO nhi_credentials (
    id, tenant_id, nhi_id, credential_type, credential_hash,
    valid_from, valid_until, is_active, rotated_by, created_at
)
SELECT
    c.id,
    c.tenant_id,
    c.nhi_id,
    c.credential_type::text,
    c.credential_hash,
    c.valid_from,
    c.valid_until,
    c.is_active,
    c.rotated_by,
    c.created_at
FROM gov_nhi_credentials c
-- Only migrate credentials whose NHI was successfully migrated
WHERE EXISTS (SELECT 1 FROM nhi_identities ni WHERE ni.id = c.nhi_id)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 5. Migrate ai_agent_tool_permissions → nhi_tool_permissions
-- ============================================================================

-- ai_agent_tool_permissions columns: id, tenant_id, agent_id, tool_id,
--   allowed_parameters (jsonb), max_calls_per_hour, requires_approval,
--   granted_at, granted_by, expires_at

INSERT INTO nhi_tool_permissions (
    id, tenant_id, agent_nhi_id, tool_nhi_id, allowed_parameters,
    max_calls_per_hour, requires_approval, granted_at, granted_by, expires_at
)
SELECT
    p.id,
    p.tenant_id,
    p.agent_id,   -- agent_id → agent_nhi_id (same UUID)
    p.tool_id,    -- tool_id → tool_nhi_id (same UUID)
    p.allowed_parameters,
    p.max_calls_per_hour,
    p.requires_approval,
    p.granted_at,
    p.granted_by,
    p.expires_at
FROM ai_agent_tool_permissions p
-- Only migrate permissions whose agent and tool were successfully migrated
WHERE EXISTS (SELECT 1 FROM nhi_identities ni WHERE ni.id = p.agent_id)
  AND EXISTS (SELECT 1 FROM nhi_identities ni WHERE ni.id = p.tool_id)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 6. Post-migration validation
-- ============================================================================

DO $$
DECLARE
    old_count BIGINT;
    new_count BIGINT;
BEGIN
    -- Validate agents
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ai_agents') THEN
        SELECT COUNT(*) INTO old_count FROM ai_agents;
        SELECT COUNT(*) INTO new_count FROM nhi_identities WHERE nhi_type = 'agent';
        IF old_count != new_count THEN
            RAISE WARNING 'NHI migration: agent count mismatch (old=%, new=%)', old_count, new_count;
        END IF;
    END IF;

    -- Validate tools
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ai_tools') THEN
        SELECT COUNT(*) INTO old_count FROM ai_tools;
        SELECT COUNT(*) INTO new_count FROM nhi_identities WHERE nhi_type = 'tool';
        IF old_count != new_count THEN
            RAISE WARNING 'NHI migration: tool count mismatch (old=%, new=%)', old_count, new_count;
        END IF;
    END IF;

    -- Validate service accounts
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'gov_service_accounts') THEN
        SELECT COUNT(*) INTO old_count FROM gov_service_accounts;
        SELECT COUNT(*) INTO new_count FROM nhi_identities WHERE nhi_type = 'service_account';
        IF old_count != new_count THEN
            RAISE WARNING 'NHI migration: service account count mismatch (old=%, new=%)', old_count, new_count;
        END IF;
    END IF;

    RAISE NOTICE 'NHI data migration validation complete';
END $$;
