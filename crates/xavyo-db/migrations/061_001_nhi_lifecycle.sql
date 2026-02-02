-- Migration: 061_001_nhi_lifecycle
-- Feature: F061 - Non-Human Identities (NHI) Lifecycle Management
-- Description: Extends service accounts with NHI lifecycle capabilities

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

-- NHI credential type
DO $$ BEGIN
    CREATE TYPE gov_nhi_credential_type AS ENUM (
        'api_key',
        'secret',
        'certificate'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- NHI usage outcome
DO $$ BEGIN
    CREATE TYPE gov_nhi_usage_outcome AS ENUM (
        'success',
        'failure',
        'denied'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- NHI request status
DO $$ BEGIN
    CREATE TYPE gov_nhi_request_status AS ENUM (
        'pending',
        'approved',
        'rejected',
        'cancelled'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- NHI suspension reason
DO $$ BEGIN
    CREATE TYPE gov_nhi_suspension_reason AS ENUM (
        'expired',
        'inactive',
        'certification_revoked',
        'emergency',
        'manual'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- NHI audit event type
DO $$ BEGIN
    CREATE TYPE gov_nhi_audit_event_type AS ENUM (
        'created',
        'updated',
        'credentials_rotated',
        'credential_revoked',
        'suspended',
        'reactivated',
        'ownership_transferred',
        'certified',
        'expired',
        'deleted',
        'emergency_suspended'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Add credential_revoked to existing enum if it exists without the value
DO $$ BEGIN
    ALTER TYPE gov_nhi_audit_event_type ADD VALUE IF NOT EXISTS 'credential_revoked' AFTER 'credentials_rotated';
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- ALTER EXISTING gov_service_accounts TABLE
-- ============================================================================

-- Add NHI lifecycle columns to existing service accounts table
ALTER TABLE gov_service_accounts
    ADD COLUMN IF NOT EXISTS backup_owner_id UUID,
    ADD COLUMN IF NOT EXISTS rotation_interval_days INTEGER DEFAULT 90,
    ADD COLUMN IF NOT EXISTS last_rotation_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS inactivity_threshold_days INTEGER DEFAULT 90,
    ADD COLUMN IF NOT EXISTS grace_period_ends_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS suspension_reason gov_nhi_suspension_reason;

-- Add constraints for new columns
DO $$ BEGIN
    ALTER TABLE gov_service_accounts
        ADD CONSTRAINT chk_rotation_interval_range
        CHECK (rotation_interval_days IS NULL OR (rotation_interval_days >= 1 AND rotation_interval_days <= 365));
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    ALTER TABLE gov_service_accounts
        ADD CONSTRAINT chk_inactivity_threshold_min
        CHECK (inactivity_threshold_days IS NULL OR inactivity_threshold_days >= 30);
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    ALTER TABLE gov_service_accounts
        ADD CONSTRAINT chk_backup_owner_different
        CHECK (backup_owner_id IS NULL OR backup_owner_id != owner_id);
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Add unique constraint on name per tenant
DO $$ BEGIN
    ALTER TABLE gov_service_accounts
        ADD CONSTRAINT uq_service_account_name_tenant UNIQUE (tenant_id, name);
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- NEW TABLES
-- ============================================================================

-- NHI Credentials table
CREATE TABLE IF NOT EXISTS gov_nhi_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    nhi_id UUID NOT NULL REFERENCES gov_service_accounts(id) ON DELETE CASCADE,
    credential_type gov_nhi_credential_type NOT NULL,
    credential_hash VARCHAR(255) NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    rotated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_valid_dates CHECK (valid_until > valid_from)
);

-- NHI Usage Events table (partitioned by timestamp for high volume)
CREATE TABLE IF NOT EXISTS gov_nhi_usage_events (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    nhi_id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    target_resource VARCHAR(500) NOT NULL,
    action VARCHAR(100) NOT NULL,
    outcome gov_nhi_usage_outcome NOT NULL,
    source_ip INET,
    user_agent VARCHAR(500),
    duration_ms INTEGER,
    metadata JSONB DEFAULT '{}',

    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create initial partitions for usage events (monthly)
CREATE TABLE IF NOT EXISTS gov_nhi_usage_events_2026_01 PARTITION OF gov_nhi_usage_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

CREATE TABLE IF NOT EXISTS gov_nhi_usage_events_2026_02 PARTITION OF gov_nhi_usage_events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE TABLE IF NOT EXISTS gov_nhi_usage_events_2026_03 PARTITION OF gov_nhi_usage_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE IF NOT EXISTS gov_nhi_usage_events_2026_04 PARTITION OF gov_nhi_usage_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE IF NOT EXISTS gov_nhi_usage_events_2026_05 PARTITION OF gov_nhi_usage_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE TABLE IF NOT EXISTS gov_nhi_usage_events_2026_06 PARTITION OF gov_nhi_usage_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

-- NHI Risk Scores table
CREATE TABLE IF NOT EXISTS gov_nhi_risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    nhi_id UUID NOT NULL REFERENCES gov_service_accounts(id) ON DELETE CASCADE,
    total_score INTEGER NOT NULL,
    risk_level gov_risk_level NOT NULL,
    staleness_factor INTEGER NOT NULL DEFAULT 0,
    credential_age_factor INTEGER NOT NULL DEFAULT 0,
    access_scope_factor INTEGER NOT NULL DEFAULT 0,
    factor_breakdown JSONB NOT NULL DEFAULT '{}',
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_calculation_at TIMESTAMPTZ,

    CONSTRAINT chk_total_score_range CHECK (total_score >= 0 AND total_score <= 100),
    CONSTRAINT uq_nhi_risk_score UNIQUE (tenant_id, nhi_id)
);

-- NHI Request table
CREATE TABLE IF NOT EXISTS gov_nhi_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    requester_id UUID NOT NULL,
    requested_name VARCHAR(200) NOT NULL,
    purpose TEXT NOT NULL,
    requested_permissions UUID[] DEFAULT '{}',
    requested_expiration TIMESTAMPTZ,
    requested_rotation_days INTEGER DEFAULT 90,
    status gov_nhi_request_status NOT NULL DEFAULT 'pending',
    approver_id UUID,
    decision_at TIMESTAMPTZ,
    decision_comments TEXT,
    created_nhi_id UUID REFERENCES gov_service_accounts(id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_request_rotation_range CHECK (requested_rotation_days IS NULL OR (requested_rotation_days >= 1 AND requested_rotation_days <= 365)),
    CONSTRAINT chk_decision_consistency CHECK (
        (status IN ('pending', 'cancelled') AND decision_at IS NULL) OR
        (status IN ('approved', 'rejected') AND decision_at IS NOT NULL)
    )
);

-- NHI Audit Events table
CREATE TABLE IF NOT EXISTS gov_nhi_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    nhi_id UUID NOT NULL,
    event_type gov_nhi_audit_event_type NOT NULL,
    actor_id UUID,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changes JSONB,
    metadata JSONB DEFAULT '{}',
    source_ip INET
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Service accounts additional indexes
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_rotation ON gov_service_accounts(tenant_id, last_rotation_at)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_last_used ON gov_service_accounts(tenant_id, last_used_at)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_backup_owner ON gov_service_accounts(tenant_id, backup_owner_id)
    WHERE backup_owner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_grace_period ON gov_service_accounts(grace_period_ends_at)
    WHERE grace_period_ends_at IS NOT NULL;

-- NHI Credentials indexes
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_hash ON gov_nhi_credentials(credential_hash)
    WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_nhi ON gov_nhi_credentials(tenant_id, nhi_id, is_active);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_expiry ON gov_nhi_credentials(valid_until)
    WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_tenant ON gov_nhi_credentials(tenant_id);

-- NHI Usage Events indexes (on parent table, inherited by partitions)
CREATE INDEX IF NOT EXISTS idx_gov_nhi_usage_nhi_time ON gov_nhi_usage_events(tenant_id, nhi_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_usage_resource ON gov_nhi_usage_events(tenant_id, target_resource, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_usage_outcome ON gov_nhi_usage_events(tenant_id, outcome, timestamp DESC);

-- NHI Risk Scores indexes
CREATE INDEX IF NOT EXISTS idx_gov_nhi_risk_level ON gov_nhi_risk_scores(tenant_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_risk_score ON gov_nhi_risk_scores(tenant_id, total_score DESC);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_risk_next_calc ON gov_nhi_risk_scores(next_calculation_at)
    WHERE next_calculation_at IS NOT NULL;

-- NHI Requests indexes
CREATE INDEX IF NOT EXISTS idx_gov_nhi_requests_requester ON gov_nhi_requests(tenant_id, requester_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_requests_pending ON gov_nhi_requests(tenant_id, status, created_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_gov_nhi_requests_expires ON gov_nhi_requests(expires_at)
    WHERE status = 'pending';

-- NHI Audit Events indexes
CREATE INDEX IF NOT EXISTS idx_gov_nhi_audit_nhi_time ON gov_nhi_audit_events(tenant_id, nhi_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_audit_type ON gov_nhi_audit_events(tenant_id, event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_gov_nhi_audit_actor ON gov_nhi_audit_events(tenant_id, actor_id, timestamp DESC)
    WHERE actor_id IS NOT NULL;

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on new tables
ALTER TABLE gov_nhi_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_nhi_usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_nhi_risk_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_nhi_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_nhi_audit_events ENABLE ROW LEVEL SECURITY;

-- RLS policies for gov_nhi_credentials
DROP POLICY IF EXISTS gov_nhi_credentials_tenant_isolation ON gov_nhi_credentials;
CREATE POLICY gov_nhi_credentials_tenant_isolation ON gov_nhi_credentials
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_nhi_usage_events
DROP POLICY IF EXISTS gov_nhi_usage_events_tenant_isolation ON gov_nhi_usage_events;
CREATE POLICY gov_nhi_usage_events_tenant_isolation ON gov_nhi_usage_events
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_nhi_risk_scores
DROP POLICY IF EXISTS gov_nhi_risk_scores_tenant_isolation ON gov_nhi_risk_scores;
CREATE POLICY gov_nhi_risk_scores_tenant_isolation ON gov_nhi_risk_scores
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_nhi_requests
DROP POLICY IF EXISTS gov_nhi_requests_tenant_isolation ON gov_nhi_requests;
CREATE POLICY gov_nhi_requests_tenant_isolation ON gov_nhi_requests
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_nhi_audit_events
DROP POLICY IF EXISTS gov_nhi_audit_events_tenant_isolation ON gov_nhi_audit_events;
CREATE POLICY gov_nhi_audit_events_tenant_isolation ON gov_nhi_audit_events
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Updated_at trigger for requests
DROP TRIGGER IF EXISTS update_gov_nhi_requests_updated_at ON gov_nhi_requests;
CREATE TRIGGER update_gov_nhi_requests_updated_at
    BEFORE UPDATE ON gov_nhi_requests
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE gov_nhi_credentials IS 'Stores hashed credentials for NHIs. Plaintext never stored.';
COMMENT ON TABLE gov_nhi_usage_events IS 'High-volume usage tracking for NHI authentication events. Partitioned by month.';
COMMENT ON TABLE gov_nhi_risk_scores IS 'Cached risk scores for NHIs with factor breakdown.';
COMMENT ON TABLE gov_nhi_requests IS 'Self-service NHI provisioning requests.';
COMMENT ON TABLE gov_nhi_audit_events IS 'Complete audit trail for NHI lifecycle events.';

COMMENT ON COLUMN gov_service_accounts.backup_owner_id IS 'Backup owner for ownership transfer on primary owner departure.';
COMMENT ON COLUMN gov_service_accounts.rotation_interval_days IS 'Days between credential rotations. Default 90.';
COMMENT ON COLUMN gov_service_accounts.last_rotation_at IS 'Timestamp of last credential rotation.';
COMMENT ON COLUMN gov_service_accounts.last_used_at IS 'Timestamp of last authentication event.';
COMMENT ON COLUMN gov_service_accounts.inactivity_threshold_days IS 'Days of inactivity before suspension warning. Default 90.';
COMMENT ON COLUMN gov_service_accounts.grace_period_ends_at IS 'When grace period after suspension warning ends.';
COMMENT ON COLUMN gov_service_accounts.suspension_reason IS 'Why NHI was suspended, if applicable.';
