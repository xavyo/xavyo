-- F037: JML Lifecycle Workflows
-- This migration creates tables for lifecycle events, birthright policies, actions, and snapshots.

-- ============================================================================
-- ENUMS
-- ============================================================================

-- Lifecycle event type
CREATE TYPE lifecycle_event_type AS ENUM ('joiner', 'mover', 'leaver');

-- Lifecycle action type
CREATE TYPE lifecycle_action_type AS ENUM ('provision', 'revoke', 'schedule_revoke', 'cancel_revoke', 'skip');

-- Birthright policy status
CREATE TYPE birthright_policy_status AS ENUM ('active', 'inactive', 'archived');

-- Access snapshot type
CREATE TYPE access_snapshot_type AS ENUM ('pre_leaver', 'pre_mover', 'current');

-- ============================================================================
-- GOV_BIRTHRIGHT_POLICIES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_birthright_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    conditions JSONB NOT NULL DEFAULT '[]',
    entitlement_ids UUID[] NOT NULL DEFAULT '{}',
    priority INTEGER NOT NULL DEFAULT 0,
    status birthright_policy_status NOT NULL DEFAULT 'active',
    grace_period_days INTEGER NOT NULL DEFAULT 7,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique policy name within tenant
    CONSTRAINT gov_birthright_policies_name_unique UNIQUE (tenant_id, name),

    -- Grace period must be non-negative
    CONSTRAINT gov_birthright_policies_grace_period_check CHECK (grace_period_days >= 0),

    -- Priority must be non-negative
    CONSTRAINT gov_birthright_policies_priority_check CHECK (priority >= 0)
);

-- Indexes for policies
CREATE INDEX IF NOT EXISTS idx_birthright_policies_tenant_status
    ON gov_birthright_policies(tenant_id, status)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_birthright_policies_priority
    ON gov_birthright_policies(tenant_id, priority DESC)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_birthright_policies_created_by
    ON gov_birthright_policies(created_by);

-- RLS for policies
ALTER TABLE gov_birthright_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_birthright_policies_tenant_isolation_select ON gov_birthright_policies
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_birthright_policies_tenant_isolation_insert ON gov_birthright_policies
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_birthright_policies_tenant_isolation_update ON gov_birthright_policies
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_birthright_policies_tenant_isolation_delete ON gov_birthright_policies
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- GOV_LIFECYCLE_EVENTS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_lifecycle_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_type lifecycle_event_type NOT NULL,
    attributes_before JSONB DEFAULT '{}',
    attributes_after JSONB DEFAULT '{}',
    source VARCHAR(50) NOT NULL DEFAULT 'api',
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for events
CREATE INDEX IF NOT EXISTS idx_lifecycle_events_tenant_user
    ON gov_lifecycle_events(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_events_type_created
    ON gov_lifecycle_events(tenant_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lifecycle_events_unprocessed
    ON gov_lifecycle_events(tenant_id, created_at)
    WHERE processed_at IS NULL;

-- RLS for events
ALTER TABLE gov_lifecycle_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_lifecycle_events_tenant_isolation_select ON gov_lifecycle_events
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_lifecycle_events_tenant_isolation_insert ON gov_lifecycle_events
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_lifecycle_events_tenant_isolation_update ON gov_lifecycle_events
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_lifecycle_events_tenant_isolation_delete ON gov_lifecycle_events
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- GOV_LIFECYCLE_ACTIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_lifecycle_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES gov_lifecycle_events(id) ON DELETE CASCADE,
    action_type lifecycle_action_type NOT NULL,
    assignment_id UUID REFERENCES gov_entitlement_assignments(id) ON DELETE SET NULL,
    policy_id UUID REFERENCES gov_birthright_policies(id) ON DELETE SET NULL,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE RESTRICT,
    scheduled_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Scheduled actions must have scheduled_at
    CONSTRAINT gov_lifecycle_actions_schedule_check
        CHECK (action_type != 'schedule_revoke' OR scheduled_at IS NOT NULL),

    -- Cannot have both executed and cancelled
    CONSTRAINT gov_lifecycle_actions_state_check
        CHECK (NOT (executed_at IS NOT NULL AND cancelled_at IS NOT NULL))
);

-- Indexes for actions
CREATE INDEX IF NOT EXISTS idx_lifecycle_actions_event
    ON gov_lifecycle_actions(event_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_actions_pending
    ON gov_lifecycle_actions(tenant_id, scheduled_at)
    WHERE executed_at IS NULL AND cancelled_at IS NULL AND scheduled_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_lifecycle_actions_assignment
    ON gov_lifecycle_actions(assignment_id)
    WHERE assignment_id IS NOT NULL;

-- RLS for actions
ALTER TABLE gov_lifecycle_actions ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_lifecycle_actions_tenant_isolation_select ON gov_lifecycle_actions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_lifecycle_actions_tenant_isolation_insert ON gov_lifecycle_actions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_lifecycle_actions_tenant_isolation_update ON gov_lifecycle_actions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_lifecycle_actions_tenant_isolation_delete ON gov_lifecycle_actions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- GOV_ACCESS_SNAPSHOTS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_access_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_id UUID NOT NULL REFERENCES gov_lifecycle_events(id) ON DELETE CASCADE,
    snapshot_type access_snapshot_type NOT NULL,
    assignments JSONB NOT NULL DEFAULT '{"assignments": [], "total_count": 0}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for snapshots
CREATE INDEX IF NOT EXISTS idx_access_snapshots_user
    ON gov_access_snapshots(tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_snapshots_event
    ON gov_access_snapshots(event_id);

-- RLS for snapshots
ALTER TABLE gov_access_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_access_snapshots_tenant_isolation_select ON gov_access_snapshots
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_access_snapshots_tenant_isolation_insert ON gov_access_snapshots
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_access_snapshots_tenant_isolation_update ON gov_access_snapshots
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_access_snapshots_tenant_isolation_delete ON gov_access_snapshots
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS: Update updated_at timestamp
-- ============================================================================

CREATE TRIGGER gov_birthright_policies_updated_at
    BEFORE UPDATE ON gov_birthright_policies
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE gov_birthright_policies IS 'Birthright access policies defining attribute-based auto-provisioning rules';
COMMENT ON TABLE gov_lifecycle_events IS 'Lifecycle events (joiner, mover, leaver) for JML workflow automation';
COMMENT ON TABLE gov_lifecycle_actions IS 'Actions taken as result of lifecycle events (provision, revoke, schedule)';
COMMENT ON TABLE gov_access_snapshots IS 'Point-in-time captures of user access for audit trail';

COMMENT ON COLUMN gov_birthright_policies.conditions IS 'JSON array of condition objects: [{attribute, operator, value}]';
COMMENT ON COLUMN gov_birthright_policies.entitlement_ids IS 'Array of entitlement UUIDs to provision when conditions match';
COMMENT ON COLUMN gov_birthright_policies.grace_period_days IS 'Days to wait before revoking entitlements on mover events';

COMMENT ON COLUMN gov_lifecycle_events.attributes_before IS 'User attributes before the change (for mover events)';
COMMENT ON COLUMN gov_lifecycle_events.attributes_after IS 'User attributes after the change (for joiner/mover events)';
COMMENT ON COLUMN gov_lifecycle_events.source IS 'Event source: api, scim, trigger, webhook';

COMMENT ON COLUMN gov_lifecycle_actions.scheduled_at IS 'When scheduled revocation should execute';
COMMENT ON COLUMN gov_lifecycle_actions.executed_at IS 'When action was actually executed';
COMMENT ON COLUMN gov_lifecycle_actions.cancelled_at IS 'When scheduled action was cancelled';

COMMENT ON COLUMN gov_access_snapshots.assignments IS 'JSON object with assignments array and total_count';
