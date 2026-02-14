-- F055: Micro-certification
-- Event-triggered certifications for high-risk assignments, SoD violations, and manager changes

-- =============================================================================
-- ENUM TYPES
-- =============================================================================

-- Trigger types for micro-certifications
CREATE TYPE micro_cert_trigger_type AS ENUM (
    'high_risk_assignment',  -- Entitlement with risk_level = high/critical assigned
    'sod_violation',         -- SoD rule violation detected
    'manager_change',        -- User's manager changed
    'periodic_recert',       -- Scheduled re-certification
    'manual'                 -- Manually triggered by admin
);

-- Scope types for trigger rules
CREATE TYPE micro_cert_scope_type AS ENUM (
    'tenant',       -- Applies to all entitlements in tenant
    'application',  -- Applies to entitlements in specific application
    'entitlement'   -- Applies to specific entitlement only
);

-- Reviewer types for determining who reviews
CREATE TYPE micro_cert_reviewer_type AS ENUM (
    'user_manager',       -- User's direct manager
    'entitlement_owner',  -- Owner of the entitlement
    'application_owner',  -- Owner of the application
    'specific_user'       -- Specific user from trigger rule
);

-- Status for micro-certifications
CREATE TYPE micro_cert_status AS ENUM (
    'pending',   -- Awaiting reviewer decision
    'approved',  -- Reviewer approved, access remains
    'revoked',   -- Reviewer rejected or auto-revoked
    'expired',   -- Deadline passed, no decision made (auto_revoke=false)
    'skipped'    -- Assignment deleted before decision
);

-- Decision types
CREATE TYPE micro_cert_decision AS ENUM (
    'approve',   -- Certify the access
    'revoke'     -- Reject/revoke the access
);

-- Event types for audit trail
CREATE TYPE micro_cert_event_type AS ENUM (
    'created',           -- Certification created
    'reminder_sent',     -- Reminder notification sent
    'escalated',         -- Escalated to backup reviewer
    'approved',          -- Reviewer approved
    'rejected',          -- Reviewer rejected
    'auto_revoked',      -- System revoked due to timeout
    'expired',           -- Deadline passed, no action taken
    'skipped',           -- Assignment deleted
    'assignment_revoked' -- Entitlement assignment was revoked
);

-- =============================================================================
-- TRIGGER RULES TABLE
-- =============================================================================

CREATE TABLE gov_micro_cert_triggers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Rule identification
    name VARCHAR(255) NOT NULL,
    trigger_type micro_cert_trigger_type NOT NULL,

    -- Scope configuration
    scope_type micro_cert_scope_type NOT NULL DEFAULT 'tenant',
    scope_id UUID, -- NULL for tenant scope, application_id or entitlement_id otherwise

    -- Reviewer configuration
    reviewer_type micro_cert_reviewer_type NOT NULL DEFAULT 'user_manager',
    specific_reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,
    fallback_reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Timeout and behavior
    timeout_secs INT NOT NULL DEFAULT 86400, -- 24 hours default
    reminder_threshold_percent INT NOT NULL DEFAULT 75 CHECK (reminder_threshold_percent BETWEEN 1 AND 99),
    auto_revoke BOOLEAN NOT NULL DEFAULT true,
    revoke_triggering_assignment BOOLEAN NOT NULL DEFAULT true, -- For SoD: revoke newer assignment

    -- Rule state
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_default BOOLEAN NOT NULL DEFAULT false,
    priority INT NOT NULL DEFAULT 0,

    -- Extensibility
    metadata JSONB,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_timeout_positive CHECK (timeout_secs > 0),
    CONSTRAINT chk_specific_reviewer CHECK (
        reviewer_type != 'specific_user' OR specific_reviewer_id IS NOT NULL
    ),
    CONSTRAINT chk_scope_id CHECK (
        (scope_type = 'tenant' AND scope_id IS NULL) OR
        (scope_type IN ('application', 'entitlement') AND scope_id IS NOT NULL)
    )
);

-- Unique constraint on name within tenant and trigger type
CREATE UNIQUE INDEX idx_micro_cert_triggers_name
    ON gov_micro_cert_triggers (tenant_id, trigger_type, name);

-- Index for finding rules by tenant and trigger type
CREATE INDEX idx_micro_cert_triggers_tenant_type
    ON gov_micro_cert_triggers (tenant_id, trigger_type)
    WHERE is_active = true;

-- Index for scope-based lookups
CREATE INDEX idx_micro_cert_triggers_scope
    ON gov_micro_cert_triggers (tenant_id, scope_type, scope_id)
    WHERE is_active = true;

-- Partial index for default rules (only one default per tenant+trigger_type)
CREATE UNIQUE INDEX idx_micro_cert_triggers_default
    ON gov_micro_cert_triggers (tenant_id, trigger_type)
    WHERE is_default = true AND is_active = true;

-- =============================================================================
-- MICRO-CERTIFICATIONS TABLE
-- =============================================================================

CREATE TABLE gov_micro_certifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- References
    trigger_rule_id UUID NOT NULL REFERENCES gov_micro_cert_triggers(id) ON DELETE RESTRICT,
    assignment_id UUID REFERENCES gov_entitlement_assignments(id) ON DELETE SET NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,

    -- Reviewer
    reviewer_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    backup_reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Status
    status micro_cert_status NOT NULL DEFAULT 'pending',

    -- Triggering event info
    triggering_event_type VARCHAR(100) NOT NULL,
    triggering_event_id UUID NOT NULL,
    triggering_event_data JSONB,

    -- Deadlines
    deadline TIMESTAMPTZ NOT NULL,
    escalation_deadline TIMESTAMPTZ,

    -- Progress tracking
    reminder_sent BOOLEAN NOT NULL DEFAULT false,
    escalated BOOLEAN NOT NULL DEFAULT false,

    -- Decision
    decision micro_cert_decision,
    decision_comment TEXT,
    decided_by UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at TIMESTAMPTZ,

    -- For SoD: which assignment was revoked
    revoked_assignment_id UUID REFERENCES gov_entitlement_assignments(id) ON DELETE SET NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_escalation_before_deadline CHECK (
        escalation_deadline IS NULL OR escalation_deadline < deadline
    ),
    CONSTRAINT chk_decision_requires_status CHECK (
        (status IN ('approved', 'revoked') AND decision IS NOT NULL AND decided_at IS NOT NULL) OR
        (status IN ('pending', 'expired', 'skipped') AND decision IS NULL)
    )
);

-- Index for listing by tenant and status
CREATE INDEX idx_micro_cert_tenant_status
    ON gov_micro_certifications (tenant_id, status);

-- Index for finding pending items by reviewer
CREATE INDEX idx_micro_cert_reviewer
    ON gov_micro_certifications (tenant_id, reviewer_id)
    WHERE status = 'pending';

-- Index for finding pending items by backup reviewer (after escalation)
CREATE INDEX idx_micro_cert_backup_reviewer
    ON gov_micro_certifications (tenant_id, backup_reviewer_id)
    WHERE status = 'pending' AND escalated = true;

-- Index for expiration job - find pending items by deadline
CREATE INDEX idx_micro_cert_deadline
    ON gov_micro_certifications (tenant_id, deadline)
    WHERE status = 'pending';

-- Index for finding certifications by assignment
CREATE INDEX idx_micro_cert_assignment
    ON gov_micro_certifications (tenant_id, assignment_id);

-- Index for finding certifications by user
CREATE INDEX idx_micro_cert_user
    ON gov_micro_certifications (tenant_id, user_id);

-- Unique partial index: prevent duplicate pending certifications for same assignment+rule
CREATE UNIQUE INDEX idx_micro_cert_pending_unique
    ON gov_micro_certifications (tenant_id, assignment_id, trigger_rule_id)
    WHERE status = 'pending' AND assignment_id IS NOT NULL;

-- =============================================================================
-- AUDIT EVENTS TABLE
-- =============================================================================

CREATE TABLE gov_micro_cert_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    micro_certification_id UUID NOT NULL REFERENCES gov_micro_certifications(id) ON DELETE CASCADE,

    -- Event info
    event_type micro_cert_event_type NOT NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL, -- NULL for system actions
    details JSONB,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for listing events by certification
CREATE INDEX idx_micro_cert_events_cert
    ON gov_micro_cert_events (micro_certification_id);

-- Index for searching events by tenant and type
CREATE INDEX idx_micro_cert_events_tenant_type
    ON gov_micro_cert_events (tenant_id, event_type);

-- Index for searching events by date range
CREATE INDEX idx_micro_cert_events_created
    ON gov_micro_cert_events (tenant_id, created_at DESC);

-- =============================================================================
-- ROW-LEVEL SECURITY
-- =============================================================================

ALTER TABLE gov_micro_cert_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_micro_certifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_micro_cert_events ENABLE ROW LEVEL SECURITY;

-- RLS Policies for triggers
CREATE POLICY tenant_isolation_micro_cert_triggers ON gov_micro_cert_triggers
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS Policies for certifications
CREATE POLICY tenant_isolation_micro_certifications ON gov_micro_certifications
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS Policies for events
CREATE POLICY tenant_isolation_micro_cert_events ON gov_micro_cert_events
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- =============================================================================
-- UPDATED_AT TRIGGERS
-- =============================================================================

CREATE TRIGGER set_updated_at_micro_cert_triggers
    BEFORE UPDATE ON gov_micro_cert_triggers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER set_updated_at_micro_certifications
    BEFORE UPDATE ON gov_micro_certifications
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
