-- Power of Attorney / Identity Assumption (F-061)
-- Enables users to grant another user the ability to act on their behalf

-- PoA status enum (reuses same values as DelegationStatus for consistency)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'poa_status') THEN
        CREATE TYPE poa_status AS ENUM ('pending', 'active', 'expired', 'revoked');
    END IF;
END$$;

-- PoA audit event type enum
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'poa_event_type') THEN
        CREATE TYPE poa_event_type AS ENUM (
            'grant_created',
            'grant_extended',
            'grant_revoked',
            'grant_expired',
            'identity_assumed',
            'identity_dropped',
            'action_performed'
        );
    END IF;
END$$;

-- Power of Attorney grants table
CREATE TABLE IF NOT EXISTS power_of_attorneys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Donor is the user granting PoA (the user being represented)
    donor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Attorney is the user receiving PoA (the user who can act on behalf)
    attorney_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Optional scope restriction (reuses existing GovDelegationScope)
    scope_id UUID REFERENCES gov_delegation_scopes(id) ON DELETE SET NULL,

    -- Validity period (max 90 days enforced at API level)
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,

    -- Lifecycle
    status poa_status NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id),

    -- Optional reason for grant/revoke
    reason TEXT,

    -- Constraints
    CONSTRAINT poa_no_self_delegation CHECK (donor_id != attorney_id),
    CONSTRAINT poa_valid_time_range CHECK (ends_at > starts_at),
    CONSTRAINT poa_max_duration CHECK (ends_at - starts_at <= INTERVAL '90 days')
);

-- Indexes for Power of Attorney
CREATE INDEX IF NOT EXISTS idx_poa_tenant_donor ON power_of_attorneys(tenant_id, donor_id);
CREATE INDEX IF NOT EXISTS idx_poa_tenant_attorney ON power_of_attorneys(tenant_id, attorney_id);
CREATE INDEX IF NOT EXISTS idx_poa_tenant_status ON power_of_attorneys(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_poa_active_at ON power_of_attorneys(tenant_id, status, starts_at, ends_at)
    WHERE status IN ('pending', 'active');

-- Row Level Security for Power of Attorney
ALTER TABLE power_of_attorneys ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON power_of_attorneys;
CREATE POLICY tenant_isolation_policy ON power_of_attorneys
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Assumed sessions table - tracks when attorney assumes donor's identity
CREATE TABLE IF NOT EXISTS poa_assumed_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Link to the PoA grant
    poa_id UUID NOT NULL REFERENCES power_of_attorneys(id) ON DELETE CASCADE,

    -- The attorney who assumed the identity
    attorney_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Session timing
    assumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dropped_at TIMESTAMPTZ,

    -- JWT tracking
    session_token_jti TEXT NOT NULL,

    -- Client context for audit
    ip_address INET,
    user_agent TEXT,

    -- Quick filter for active sessions
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Termination reason
    terminated_reason TEXT
);

-- Indexes for Assumed Sessions
CREATE INDEX IF NOT EXISTS idx_poa_session_active ON poa_assumed_sessions(tenant_id, poa_id, is_active)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_poa_session_jti ON poa_assumed_sessions(session_token_jti);
CREATE INDEX IF NOT EXISTS idx_poa_session_attorney ON poa_assumed_sessions(tenant_id, attorney_id, is_active)
    WHERE is_active = TRUE;

-- Row Level Security for Assumed Sessions
ALTER TABLE poa_assumed_sessions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON poa_assumed_sessions;
CREATE POLICY tenant_isolation_policy ON poa_assumed_sessions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Audit events table - immutable audit trail for PoA operations
CREATE TABLE IF NOT EXISTS poa_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Link to the PoA grant
    poa_id UUID NOT NULL REFERENCES power_of_attorneys(id) ON DELETE CASCADE,

    -- Event type
    event_type poa_event_type NOT NULL,

    -- Who performed the action
    actor_id UUID NOT NULL REFERENCES users(id),

    -- User affected (if different from actor, e.g., the donor for assumed actions)
    affected_user_id UUID REFERENCES users(id),

    -- Event details as JSON
    details JSONB,

    -- Client context
    ip_address INET,
    user_agent TEXT,

    -- Immutable timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for Audit Events
CREATE INDEX IF NOT EXISTS idx_poa_audit_tenant_poa ON poa_audit_events(tenant_id, poa_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_poa_audit_tenant_actor ON poa_audit_events(tenant_id, actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_poa_audit_tenant_type ON poa_audit_events(tenant_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_poa_audit_affected ON poa_audit_events(tenant_id, affected_user_id, created_at DESC)
    WHERE affected_user_id IS NOT NULL;

-- Row Level Security for Audit Events
ALTER TABLE poa_audit_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON poa_audit_events;
CREATE POLICY tenant_isolation_policy ON poa_audit_events
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Function to check if a PoA is currently active
CREATE OR REPLACE FUNCTION is_poa_active(poa_id UUID, at_time TIMESTAMPTZ DEFAULT NOW())
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM power_of_attorneys
        WHERE id = poa_id
          AND status = 'active'
          AND starts_at <= at_time
          AND ends_at > at_time
    );
$$ LANGUAGE SQL STABLE;

-- Function to terminate all assumed sessions for a PoA
CREATE OR REPLACE FUNCTION terminate_poa_sessions(p_poa_id UUID, p_reason TEXT DEFAULT 'poa_revoked')
RETURNS INTEGER AS $$
DECLARE
    rows_affected INTEGER;
BEGIN
    UPDATE poa_assumed_sessions
    SET is_active = FALSE,
        dropped_at = NOW(),
        terminated_reason = p_reason
    WHERE poa_id = p_poa_id
      AND is_active = TRUE;

    GET DIAGNOSTICS rows_affected = ROW_COUNT;
    RETURN rows_affected;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-terminate sessions when PoA is revoked
CREATE OR REPLACE FUNCTION on_poa_revoked()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status != 'revoked' AND NEW.status = 'revoked' THEN
        PERFORM terminate_poa_sessions(NEW.id, 'poa_revoked');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_poa_revoked ON power_of_attorneys;
CREATE TRIGGER trg_poa_revoked
    AFTER UPDATE ON power_of_attorneys
    FOR EACH ROW
    EXECUTE FUNCTION on_poa_revoked();
