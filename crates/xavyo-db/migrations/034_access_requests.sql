-- F035: Access Request Workflows
-- This migration creates tables for access request workflows, approval chains, and delegation.

-- ============================================================================
-- ENUMS
-- ============================================================================

-- Approver types for workflow steps
CREATE TYPE gov_approver_type AS ENUM ('manager', 'entitlement_owner', 'specific_users');

-- Status for access requests
CREATE TYPE gov_request_status AS ENUM (
    'pending',           -- Awaiting first approval
    'pending_approval',  -- In approval chain
    'approved',          -- Fully approved, pending provisioning
    'provisioned',       -- Access granted
    'rejected',          -- Rejected by approver
    'cancelled',         -- Cancelled by requester
    'expired',           -- Auto-expired due to timeout
    'failed'             -- Provisioning failed
);

-- Decision types for approvals
CREATE TYPE gov_approval_decision AS ENUM ('approved', 'rejected');

-- ============================================================================
-- APPROVAL WORKFLOWS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_approval_workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name per tenant
    CONSTRAINT gov_approval_workflows_tenant_name_unique UNIQUE (tenant_id, name)
);

-- Partial unique index: only one default workflow per tenant
CREATE UNIQUE INDEX gov_approval_workflows_unique_default ON gov_approval_workflows (tenant_id)
    WHERE is_default = TRUE;

-- Indexes for workflows
CREATE INDEX IF NOT EXISTS idx_gov_approval_workflows_tenant ON gov_approval_workflows(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_approval_workflows_tenant_active ON gov_approval_workflows(tenant_id, is_active);

-- RLS for workflows
ALTER TABLE gov_approval_workflows ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_approval_workflows_tenant_isolation_select ON gov_approval_workflows
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_workflows_tenant_isolation_insert ON gov_approval_workflows
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_workflows_tenant_isolation_update ON gov_approval_workflows
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_workflows_tenant_isolation_delete ON gov_approval_workflows
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- APPROVAL STEPS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_approval_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES gov_approval_workflows(id) ON DELETE CASCADE,
    step_order INTEGER NOT NULL,
    approver_type gov_approver_type NOT NULL,
    specific_approvers UUID[] DEFAULT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Step order must be positive
    CONSTRAINT gov_approval_steps_positive_order CHECK (step_order > 0),

    -- Unique step order within workflow
    CONSTRAINT gov_approval_steps_workflow_order_unique UNIQUE (workflow_id, step_order),

    -- specific_approvers required when approver_type is 'specific_users'
    CONSTRAINT gov_approval_steps_specific_approvers_check CHECK (
        (approver_type = 'specific_users' AND specific_approvers IS NOT NULL AND array_length(specific_approvers, 1) > 0)
        OR (approver_type != 'specific_users' AND specific_approvers IS NULL)
    )
);

-- Indexes for steps
CREATE INDEX IF NOT EXISTS idx_gov_approval_steps_workflow ON gov_approval_steps(workflow_id, step_order);

-- ============================================================================
-- ACCESS REQUESTS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE RESTRICT,
    workflow_id UUID REFERENCES gov_approval_workflows(id) ON DELETE SET NULL,
    current_step INTEGER NOT NULL DEFAULT 0,
    status gov_request_status NOT NULL DEFAULT 'pending',
    justification TEXT NOT NULL,
    requested_expires_at TIMESTAMPTZ,
    has_sod_warning BOOLEAN NOT NULL DEFAULT FALSE,
    sod_violations JSONB,
    provisioned_assignment_id UUID REFERENCES gov_entitlement_assignments(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    -- Justification must be at least 20 characters
    CONSTRAINT gov_access_requests_justification_min_length CHECK (length(trim(justification)) >= 20),

    -- Current step must be non-negative
    CONSTRAINT gov_access_requests_valid_step CHECK (current_step >= 0)
);

-- Indexes for requests
CREATE INDEX IF NOT EXISTS idx_gov_access_requests_tenant_status ON gov_access_requests(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_access_requests_requester ON gov_access_requests(tenant_id, requester_id);
CREATE INDEX IF NOT EXISTS idx_gov_access_requests_entitlement ON gov_access_requests(tenant_id, entitlement_id);
CREATE INDEX IF NOT EXISTS idx_gov_access_requests_pending_expires ON gov_access_requests(expires_at)
    WHERE status IN ('pending', 'pending_approval');

-- RLS for requests
ALTER TABLE gov_access_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_access_requests_tenant_isolation_select ON gov_access_requests
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_access_requests_tenant_isolation_insert ON gov_access_requests
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_access_requests_tenant_isolation_update ON gov_access_requests
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_access_requests_tenant_isolation_delete ON gov_access_requests
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- APPROVAL DECISIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_approval_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES gov_access_requests(id) ON DELETE CASCADE,
    step_order INTEGER NOT NULL,
    approver_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    delegate_id UUID REFERENCES users(id) ON DELETE SET NULL,
    decision gov_approval_decision NOT NULL,
    comments TEXT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Comments required for rejection
    CONSTRAINT gov_approval_decisions_rejection_comments CHECK (
        decision = 'approved' OR (decision = 'rejected' AND comments IS NOT NULL AND length(trim(comments)) > 0)
    )
);

-- Indexes for decisions
CREATE INDEX IF NOT EXISTS idx_gov_approval_decisions_request ON gov_approval_decisions(request_id, step_order);
CREATE INDEX IF NOT EXISTS idx_gov_approval_decisions_approver ON gov_approval_decisions(approver_id, decided_at);

-- ============================================================================
-- APPROVAL DELEGATIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_approval_delegations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    delegator_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    delegate_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,

    -- Delegation cannot be to self
    CONSTRAINT gov_approval_delegations_not_self CHECK (delegator_id != delegate_id),

    -- End must be after start
    CONSTRAINT gov_approval_delegations_valid_period CHECK (ends_at > starts_at)
);

-- Partial unique index: prevent overlapping active delegations for same delegator
CREATE UNIQUE INDEX gov_approval_delegations_unique_active ON gov_approval_delegations (tenant_id, delegator_id)
    WHERE is_active = TRUE;

-- Indexes for delegations
CREATE INDEX IF NOT EXISTS idx_gov_approval_delegations_tenant_active ON gov_approval_delegations(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_gov_approval_delegations_delegator ON gov_approval_delegations(tenant_id, delegator_id, is_active);
CREATE INDEX IF NOT EXISTS idx_gov_approval_delegations_delegate ON gov_approval_delegations(tenant_id, delegate_id, is_active);
CREATE INDEX IF NOT EXISTS idx_gov_approval_delegations_active_period ON gov_approval_delegations(tenant_id, starts_at, ends_at)
    WHERE is_active = TRUE;

-- RLS for delegations
ALTER TABLE gov_approval_delegations ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_approval_delegations_tenant_isolation_select ON gov_approval_delegations
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_delegations_tenant_isolation_insert ON gov_approval_delegations
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_delegations_tenant_isolation_update ON gov_approval_delegations
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY gov_approval_delegations_tenant_isolation_delete ON gov_approval_delegations
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS: Update updated_at timestamp
-- ============================================================================

CREATE TRIGGER gov_approval_workflows_updated_at
    BEFORE UPDATE ON gov_approval_workflows
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();

CREATE TRIGGER gov_access_requests_updated_at
    BEFORE UPDATE ON gov_access_requests
    FOR EACH ROW
    EXECUTE FUNCTION gov_update_updated_at();
