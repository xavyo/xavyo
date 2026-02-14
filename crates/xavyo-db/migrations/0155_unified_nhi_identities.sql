-- Migration 1191: Create unified nhi_identities base table
-- Part of 201-tool-nhi-promotion: single table for all non-human identities
-- (service accounts, agents, tools) with consistent governance fields.

-- Create the base table
CREATE TABLE IF NOT EXISTS nhi_identities (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    nhi_type        TEXT        NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    owner_id        UUID,
    backup_owner_id UUID,
    lifecycle_state TEXT        NOT NULL DEFAULT 'active',
    suspension_reason TEXT,
    expires_at      TIMESTAMPTZ,
    last_activity_at TIMESTAMPTZ,
    inactivity_threshold_days INTEGER DEFAULT 90,
    grace_period_ends_at TIMESTAMPTZ,
    risk_score      INTEGER     DEFAULT 0,
    last_certified_at TIMESTAMPTZ,
    next_certification_at TIMESTAMPTZ,
    last_certified_by UUID,
    rotation_interval_days INTEGER,
    last_rotation_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID,

    CONSTRAINT nhi_identities_pkey PRIMARY KEY (id),
    CONSTRAINT nhi_identities_tenant_type_name_unique UNIQUE (tenant_id, nhi_type, name),

    -- Type discriminator
    CONSTRAINT nhi_identities_type_check CHECK (
        nhi_type IN ('service_account', 'agent', 'tool')
    ),
    -- Lifecycle state
    CONSTRAINT nhi_identities_lifecycle_check CHECK (
        lifecycle_state IN ('active', 'inactive', 'suspended', 'deprecated', 'archived')
    ),
    -- Risk score range
    CONSTRAINT nhi_identities_risk_score_check CHECK (
        risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)
    ),
    -- Inactivity threshold minimum
    CONSTRAINT nhi_identities_inactivity_threshold_check CHECK (
        inactivity_threshold_days IS NULL OR inactivity_threshold_days >= 1
    ),
    -- Rotation interval range
    CONSTRAINT nhi_identities_rotation_interval_check CHECK (
        rotation_interval_days IS NULL OR (rotation_interval_days >= 1 AND rotation_interval_days <= 365)
    ),
    -- Owner and backup owner must differ (when both are set)
    CONSTRAINT nhi_identities_owner_backup_differ CHECK (
        owner_id IS NULL OR backup_owner_id IS NULL OR owner_id <> backup_owner_id
    ),

    -- Foreign keys
    CONSTRAINT nhi_identities_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT nhi_identities_owner_fk FOREIGN KEY (owner_id) REFERENCES users(id),
    CONSTRAINT nhi_identities_backup_owner_fk FOREIGN KEY (backup_owner_id) REFERENCES users(id),
    CONSTRAINT nhi_identities_created_by_fk FOREIGN KEY (created_by) REFERENCES users(id),
    CONSTRAINT nhi_identities_certified_by_fk FOREIGN KEY (last_certified_by) REFERENCES users(id)
);

-- Indexes (8 total)
CREATE INDEX IF NOT EXISTS idx_nhi_identities_tenant_type
    ON nhi_identities (tenant_id, nhi_type);

CREATE INDEX IF NOT EXISTS idx_nhi_identities_tenant_lifecycle
    ON nhi_identities (tenant_id, lifecycle_state);

CREATE INDEX IF NOT EXISTS idx_nhi_identities_owner
    ON nhi_identities (tenant_id, owner_id);

CREATE INDEX IF NOT EXISTS idx_nhi_identities_backup_owner
    ON nhi_identities (tenant_id, backup_owner_id);

CREATE INDEX IF NOT EXISTS idx_nhi_identities_last_activity
    ON nhi_identities (tenant_id, last_activity_at)
    WHERE lifecycle_state = 'active';

CREATE INDEX IF NOT EXISTS idx_nhi_identities_next_cert
    ON nhi_identities (tenant_id, next_certification_at)
    WHERE lifecycle_state = 'active';

CREATE INDEX IF NOT EXISTS idx_nhi_identities_expires
    ON nhi_identities (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_nhi_identities_risk_score
    ON nhi_identities (tenant_id, risk_score DESC);

-- Enable RLS
ALTER TABLE nhi_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE nhi_identities FORCE ROW LEVEL SECURITY;

-- RLS policy for xavyo_app role
DROP POLICY IF EXISTS nhi_identities_tenant_isolation ON nhi_identities;
CREATE POLICY nhi_identities_tenant_isolation ON nhi_identities
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Grant permissions to application role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xavyo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_identities TO xavyo_app;
    END IF;
END $$;
