-- F054: Workflow Escalation
-- Extends access request workflows with automatic escalation when approval steps timeout.
--
-- Key capabilities:
-- 1. Configurable timeout per approval step with escalation rules
-- 2. Escalation to manager hierarchy when approver is unavailable
-- 3. Escalation to backup approvers or approval groups
-- 4. Multiple escalation levels (first to backup, then to manager, then to admin)
-- 5. Notification to original approver and escalation target
-- 6. Audit trail of escalation events
-- 7. Configurable escalation policies per workflow or tenant-wide defaults

-- ============================================================================
-- ENUMS
-- ============================================================================

-- Escalation target types
CREATE TYPE gov_escalation_target_type AS ENUM (
    'specific_user',     -- Escalate to a specific user
    'approval_group',    -- Escalate to all members of an approval group
    'manager',           -- Escalate to the approver's direct manager
    'manager_chain',     -- Escalate up the manager chain (configurable depth)
    'tenant_admin'       -- Escalate to tenant administrators
);

-- Final fallback actions when all escalation levels are exhausted
CREATE TYPE gov_final_fallback_action AS ENUM (
    'escalate_admin',    -- Escalate to tenant admin
    'auto_approve',      -- Automatically approve the request
    'auto_reject',       -- Automatically reject the request
    'remain_pending'     -- Keep pending with admin alert
);

-- Reason for escalation
CREATE TYPE gov_escalation_reason AS ENUM (
    'timeout',           -- Escalated due to timeout
    'manual_escalation', -- Manually escalated by admin
    'target_unavailable' -- Previous target was unavailable
);

-- ============================================================================
-- USER MANAGER HIERARCHY
-- ============================================================================

-- Add manager_id to users table for manager hierarchy support
ALTER TABLE users ADD COLUMN IF NOT EXISTS manager_id UUID REFERENCES users(id);

-- Index for efficient manager lookups
CREATE INDEX IF NOT EXISTS idx_users_manager_id ON users(tenant_id, manager_id) WHERE manager_id IS NOT NULL;

-- Prevent self-manager assignment
ALTER TABLE users ADD CONSTRAINT chk_users_not_self_manager CHECK (manager_id IS NULL OR manager_id != id);

-- ============================================================================
-- APPROVAL GROUPS
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_approval_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    member_ids UUID[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_approval_groups_tenant_name UNIQUE (tenant_id, name)
);

-- RLS for approval groups
ALTER TABLE gov_approval_groups ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_approval_groups_tenant_isolation ON gov_approval_groups
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Index for member lookups
CREATE INDEX idx_approval_groups_members ON gov_approval_groups USING GIN(member_ids);

-- ============================================================================
-- ESCALATION POLICIES (Tenant Defaults)
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_escalation_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    default_timeout INTERVAL NOT NULL DEFAULT '48 hours',
    warning_threshold INTERVAL DEFAULT '4 hours',
    final_fallback gov_final_fallback_action NOT NULL DEFAULT 'remain_pending',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_escalation_policies_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT chk_warning_threshold CHECK (warning_threshold IS NULL OR warning_threshold < default_timeout)
);

-- RLS for escalation policies
ALTER TABLE gov_escalation_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_escalation_policies_tenant_isolation ON gov_escalation_policies
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Only one active default policy per tenant
CREATE UNIQUE INDEX IF NOT EXISTS idx_escalation_policies_tenant_default
    ON gov_escalation_policies (tenant_id)
    WHERE is_active = true;

-- ============================================================================
-- ESCALATION RULES (Step-specific)
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_escalation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    step_id UUID NOT NULL REFERENCES gov_approval_steps(id) ON DELETE CASCADE,
    timeout INTERVAL NOT NULL,
    warning_threshold INTERVAL,
    final_fallback gov_final_fallback_action,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_escalation_rules_step UNIQUE (step_id),
    CONSTRAINT chk_rule_warning_threshold CHECK (warning_threshold IS NULL OR warning_threshold < timeout)
);

-- RLS for escalation rules
ALTER TABLE gov_escalation_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_escalation_rules_tenant_isolation ON gov_escalation_rules
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Index for step lookups
CREATE INDEX idx_escalation_rules_step ON gov_escalation_rules(step_id);

-- ============================================================================
-- ESCALATION LEVELS
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_escalation_levels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES gov_escalation_policies(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES gov_escalation_rules(id) ON DELETE CASCADE,
    level_order INT NOT NULL,
    level_name VARCHAR(100),
    target_type gov_escalation_target_type NOT NULL,
    target_id UUID, -- For specific_user and approval_group
    manager_chain_depth INT DEFAULT 1, -- For manager_chain type
    timeout INTERVAL NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Must belong to exactly one of policy or rule
    CONSTRAINT chk_escalation_level_parent CHECK (
        (policy_id IS NOT NULL AND rule_id IS NULL) OR
        (policy_id IS NULL AND rule_id IS NOT NULL)
    ),
    -- target_id required for specific_user and approval_group
    CONSTRAINT chk_escalation_level_target CHECK (
        (target_type IN ('specific_user', 'approval_group') AND target_id IS NOT NULL) OR
        (target_type IN ('manager', 'manager_chain', 'tenant_admin') AND target_id IS NULL)
    ),
    -- manager_chain_depth only for manager_chain
    CONSTRAINT chk_manager_chain_depth CHECK (
        target_type != 'manager_chain' OR (manager_chain_depth >= 1 AND manager_chain_depth <= 10)
    )
);

-- RLS for escalation levels
ALTER TABLE gov_escalation_levels ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_escalation_levels_tenant_isolation ON gov_escalation_levels
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Unique level order per policy
CREATE UNIQUE INDEX IF NOT EXISTS idx_escalation_levels_policy_order
    ON gov_escalation_levels (policy_id, level_order)
    WHERE policy_id IS NOT NULL;

-- Unique level order per rule
CREATE UNIQUE INDEX IF NOT EXISTS idx_escalation_levels_rule_order
    ON gov_escalation_levels (rule_id, level_order)
    WHERE rule_id IS NOT NULL;

-- Indexes for lookups
CREATE INDEX idx_escalation_levels_policy ON gov_escalation_levels(policy_id) WHERE policy_id IS NOT NULL;
CREATE INDEX idx_escalation_levels_rule ON gov_escalation_levels(rule_id) WHERE rule_id IS NOT NULL;

-- ============================================================================
-- ESCALATION EVENTS (Audit Trail)
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_escalation_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id UUID NOT NULL REFERENCES gov_access_requests(id) ON DELETE CASCADE,
    step_order INT NOT NULL,
    escalation_level INT NOT NULL,
    original_approver_id UUID REFERENCES users(id),
    escalation_target_type gov_escalation_target_type NOT NULL,
    escalation_target_ids UUID[] NOT NULL,
    reason gov_escalation_reason NOT NULL,
    previous_deadline TIMESTAMPTZ,
    new_deadline TIMESTAMPTZ,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RLS for escalation events
ALTER TABLE gov_escalation_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_escalation_events_tenant_isolation ON gov_escalation_events
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- Indexes for querying (FR-017)
CREATE INDEX idx_escalation_events_request ON gov_escalation_events(tenant_id, request_id);
CREATE INDEX idx_escalation_events_approver ON gov_escalation_events(tenant_id, original_approver_id);
CREATE INDEX idx_escalation_events_date ON gov_escalation_events(tenant_id, created_at);
CREATE INDEX idx_escalation_events_targets ON gov_escalation_events USING GIN(escalation_target_ids);

-- ============================================================================
-- ACCESS REQUEST EXTENSIONS
-- ============================================================================

-- Add escalation tracking fields to access requests
ALTER TABLE gov_access_requests ADD COLUMN IF NOT EXISTS current_escalation_level INT NOT NULL DEFAULT 0;
ALTER TABLE gov_access_requests ADD COLUMN IF NOT EXISTS current_deadline TIMESTAMPTZ;
ALTER TABLE gov_access_requests ADD COLUMN IF NOT EXISTS escalation_warning_sent BOOLEAN NOT NULL DEFAULT false;

-- Index for escalation job queries
CREATE INDEX IF NOT EXISTS idx_access_requests_deadline
    ON gov_access_requests (tenant_id, current_deadline)
    WHERE status IN ('pending', 'pending_approval') AND current_deadline IS NOT NULL;

-- Index for warning notifications
CREATE INDEX IF NOT EXISTS idx_access_requests_warning
    ON gov_access_requests (tenant_id, current_deadline)
    WHERE status IN ('pending', 'pending_approval')
      AND current_deadline IS NOT NULL
      AND escalation_warning_sent = false;

-- ============================================================================
-- APPROVAL STEP EXTENSIONS
-- ============================================================================

-- Add escalation_enabled field to approval steps
ALTER TABLE gov_approval_steps ADD COLUMN IF NOT EXISTS escalation_enabled BOOLEAN NOT NULL DEFAULT true;

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to get managers recursively up to a specified depth
CREATE OR REPLACE FUNCTION get_manager_chain(
    p_user_id UUID,
    p_tenant_id UUID,
    p_max_depth INT DEFAULT 10
)
RETURNS TABLE (
    manager_id UUID,
    depth INT
) AS $$
WITH RECURSIVE manager_chain AS (
    -- Base case: get the user's direct manager
    SELECT u.manager_id, 1 AS depth
    FROM users u
    WHERE u.id = p_user_id
      AND u.tenant_id = p_tenant_id
      AND u.manager_id IS NOT NULL

    UNION ALL

    -- Recursive case: get each manager's manager
    SELECT u.manager_id, mc.depth + 1
    FROM manager_chain mc
    JOIN users u ON u.id = mc.manager_id
    WHERE u.tenant_id = p_tenant_id
      AND u.manager_id IS NOT NULL
      AND mc.depth < p_max_depth
      -- Prevent infinite loops
      AND u.manager_id != p_user_id
)
SELECT mc.manager_id, mc.depth
FROM manager_chain mc
ORDER BY mc.depth;
$$ LANGUAGE SQL STABLE;

-- Function to get tenant admin user IDs
CREATE OR REPLACE FUNCTION get_tenant_admin_ids(p_tenant_id UUID)
RETURNS UUID[] AS $$
    SELECT COALESCE(
        ARRAY_AGG(ua.user_id),
        ARRAY[]::UUID[]
    )
    FROM user_admin_assignments ua
    JOIN admin_role_templates art ON ua.template_id = art.id
    WHERE ua.tenant_id = p_tenant_id
      AND art.name = 'tenant_admin'
      AND ua.revoked_at IS NULL
      AND (ua.expires_at IS NULL OR ua.expires_at > NOW());
$$ LANGUAGE SQL STABLE;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE gov_approval_groups IS 'Reusable groups of approvers for workflow escalation';
COMMENT ON TABLE gov_escalation_policies IS 'Tenant-wide default escalation configuration';
COMMENT ON TABLE gov_escalation_rules IS 'Step-specific escalation configuration (overrides tenant defaults)';
COMMENT ON TABLE gov_escalation_levels IS 'Individual escalation levels within a policy or rule';
COMMENT ON TABLE gov_escalation_events IS 'Audit trail of escalation occurrences';

COMMENT ON COLUMN users.manager_id IS 'Manager hierarchy for escalation support (F054)';
COMMENT ON COLUMN gov_access_requests.current_escalation_level IS 'Current escalation level (0 = no escalation)';
COMMENT ON COLUMN gov_access_requests.current_deadline IS 'Deadline for current step/level action';
COMMENT ON COLUMN gov_access_requests.escalation_warning_sent IS 'Whether pre-escalation warning was sent';
COMMENT ON COLUMN gov_approval_steps.escalation_enabled IS 'Whether escalation is enabled for this step';
