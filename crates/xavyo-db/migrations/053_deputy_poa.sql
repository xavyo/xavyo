-- Migration: 053_deputy_poa.sql
-- Feature: F053 Deputy & Power of Attorney
-- Description: Extends delegation system with scope restrictions, audit trail, and lifecycle management

-- ============================================================================
-- 1. Create enum types
-- ============================================================================

-- Delegation status enum
DO $$ BEGIN
    CREATE TYPE gov_delegation_status AS ENUM (
        'pending',   -- Scheduled but not yet active
        'active',    -- Currently active
        'expired',   -- Expired by end date
        'revoked'    -- Manually revoked
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Delegation action type for audit
DO $$ BEGIN
    CREATE TYPE gov_delegation_action AS ENUM (
        'approve_request',     -- Approved access request
        'reject_request',      -- Rejected access request
        'certify_access',      -- Certified item in campaign
        'revoke_access',       -- Revoked access in certification
        'approve_transition',  -- Approved state transition
        'reject_transition'    -- Rejected state transition
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Work item type enum
DO $$ BEGIN
    CREATE TYPE gov_work_item_type AS ENUM (
        'access_request',    -- Access request approval
        'certification',     -- Certification campaign item
        'state_transition'   -- Lifecycle state transition
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- 2. Create delegation scopes table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_delegation_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,

    -- Scope restrictions (empty arrays = no restriction for that type)
    application_ids UUID[] DEFAULT '{}',
    entitlement_ids UUID[] DEFAULT '{}',
    role_ids UUID[] DEFAULT '{}',
    workflow_types TEXT[] DEFAULT '{}',

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Foreign keys
    CONSTRAINT fk_delegation_scope_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Enable RLS
ALTER TABLE gov_delegation_scopes ENABLE ROW LEVEL SECURITY;

-- RLS policies
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_delegation_scopes;
CREATE POLICY tenant_isolation_policy ON gov_delegation_scopes
    FOR ALL
    USING (tenant_id = COALESCE(
        NULLIF(current_setting('app.current_tenant', true), '')::uuid,
        tenant_id
    ));

-- Indexes
CREATE INDEX IF NOT EXISTS idx_delegation_scopes_tenant
    ON gov_delegation_scopes(tenant_id);

-- ============================================================================
-- 3. Create delegation audit table
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_delegation_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,

    -- Delegation reference
    delegation_id UUID NOT NULL,

    -- Identity tracking
    deputy_id UUID NOT NULL,      -- User who acted
    delegator_id UUID NOT NULL,   -- On whose behalf

    -- Action details
    action_type gov_delegation_action NOT NULL,
    work_item_id UUID NOT NULL,
    work_item_type gov_work_item_type NOT NULL,

    -- Additional context
    metadata JSONB DEFAULT '{}',

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Foreign keys
    CONSTRAINT fk_delegation_audit_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_delegation_audit_delegation
        FOREIGN KEY (delegation_id) REFERENCES gov_approval_delegations(id) ON DELETE CASCADE
);

-- Enable RLS
ALTER TABLE gov_delegation_audit ENABLE ROW LEVEL SECURITY;

-- RLS policies
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_delegation_audit;
CREATE POLICY tenant_isolation_policy ON gov_delegation_audit
    FOR ALL
    USING (tenant_id = COALESCE(
        NULLIF(current_setting('app.current_tenant', true), '')::uuid,
        tenant_id
    ));

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_delegation_audit_tenant
    ON gov_delegation_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_delegation_audit_delegation
    ON gov_delegation_audit(delegation_id);
CREATE INDEX IF NOT EXISTS idx_delegation_audit_deputy
    ON gov_delegation_audit(deputy_id);
CREATE INDEX IF NOT EXISTS idx_delegation_audit_delegator
    ON gov_delegation_audit(delegator_id);
CREATE INDEX IF NOT EXISTS idx_delegation_audit_created
    ON gov_delegation_audit(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_delegation_audit_work_item
    ON gov_delegation_audit(work_item_id);

-- ============================================================================
-- 4. Extend existing gov_approval_delegations table
-- ============================================================================

-- Add scope_id column
ALTER TABLE gov_approval_delegations
ADD COLUMN IF NOT EXISTS scope_id UUID REFERENCES gov_delegation_scopes(id) ON DELETE SET NULL;

-- Add status column with default based on current state
ALTER TABLE gov_approval_delegations
ADD COLUMN IF NOT EXISTS status gov_delegation_status DEFAULT 'pending';

-- Add expiry warning tracking
ALTER TABLE gov_approval_delegations
ADD COLUMN IF NOT EXISTS expiry_warning_sent BOOLEAN DEFAULT FALSE;

-- Migrate existing data: set status based on current state
UPDATE gov_approval_delegations SET status =
    CASE
        WHEN revoked_at IS NOT NULL THEN 'revoked'::gov_delegation_status
        WHEN ends_at <= NOW() THEN 'expired'::gov_delegation_status
        WHEN starts_at <= NOW() AND is_active = TRUE THEN 'active'::gov_delegation_status
        ELSE 'pending'::gov_delegation_status
    END
WHERE status IS NULL;

-- Make status NOT NULL after migration
ALTER TABLE gov_approval_delegations
ALTER COLUMN status SET NOT NULL;

-- Add indexes for new columns
CREATE INDEX IF NOT EXISTS idx_delegations_status
    ON gov_approval_delegations(status);
CREATE INDEX IF NOT EXISTS idx_delegations_scope
    ON gov_approval_delegations(scope_id) WHERE scope_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_delegations_starts_at
    ON gov_approval_delegations(starts_at);
CREATE INDEX IF NOT EXISTS idx_delegations_ends_at
    ON gov_approval_delegations(ends_at);

-- Composite index for lifecycle processing
CREATE INDEX IF NOT EXISTS idx_delegations_lifecycle
    ON gov_approval_delegations(tenant_id, status, starts_at, ends_at);

-- Composite index for finding active delegations for a delegate
CREATE INDEX IF NOT EXISTS idx_delegations_active_delegate
    ON gov_approval_delegations(tenant_id, delegate_id, status, starts_at, ends_at)
    WHERE status = 'active';

-- ============================================================================
-- 5. Create helper functions
-- ============================================================================

-- Function to check if a delegation is currently active
CREATE OR REPLACE FUNCTION is_delegation_currently_active(
    p_delegation_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
    v_is_active BOOLEAN;
BEGIN
    SELECT (status = 'active' AND starts_at <= NOW() AND ends_at > NOW())
    INTO v_is_active
    FROM gov_approval_delegations
    WHERE id = p_delegation_id;

    RETURN COALESCE(v_is_active, FALSE);
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to check if work item matches delegation scope
-- Returns TRUE if:
-- 1. Delegation has no scope (scope_id IS NULL) = full delegation
-- 2. Work item matches at least one criterion in scope (OR semantics)
CREATE OR REPLACE FUNCTION work_item_matches_delegation_scope(
    p_delegation_id UUID,
    p_application_id UUID,
    p_entitlement_id UUID,
    p_role_id UUID,
    p_workflow_type TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    v_scope_id UUID;
    v_scope RECORD;
BEGIN
    -- Get scope_id for delegation
    SELECT scope_id INTO v_scope_id
    FROM gov_approval_delegations
    WHERE id = p_delegation_id;

    -- No scope = full delegation, matches everything
    IF v_scope_id IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Get scope details
    SELECT * INTO v_scope
    FROM gov_delegation_scopes
    WHERE id = v_scope_id;

    IF v_scope IS NULL THEN
        -- Scope was deleted, treat as full delegation
        RETURN TRUE;
    END IF;

    -- Check if work item matches any scope criterion (OR semantics)
    -- Empty array = no restriction for that type

    -- Check application match
    IF p_application_id IS NOT NULL AND
       array_length(v_scope.application_ids, 1) > 0 AND
       p_application_id = ANY(v_scope.application_ids) THEN
        RETURN TRUE;
    END IF;

    -- Check entitlement match
    IF p_entitlement_id IS NOT NULL AND
       array_length(v_scope.entitlement_ids, 1) > 0 AND
       p_entitlement_id = ANY(v_scope.entitlement_ids) THEN
        RETURN TRUE;
    END IF;

    -- Check role match
    IF p_role_id IS NOT NULL AND
       array_length(v_scope.role_ids, 1) > 0 AND
       p_role_id = ANY(v_scope.role_ids) THEN
        RETURN TRUE;
    END IF;

    -- Check workflow type match
    IF p_workflow_type IS NOT NULL AND
       array_length(v_scope.workflow_types, 1) > 0 AND
       p_workflow_type = ANY(v_scope.workflow_types) THEN
        RETURN TRUE;
    END IF;

    -- If scope has at least one restriction but none matched, return FALSE
    IF array_length(v_scope.application_ids, 1) > 0 OR
       array_length(v_scope.entitlement_ids, 1) > 0 OR
       array_length(v_scope.role_ids, 1) > 0 OR
       array_length(v_scope.workflow_types, 1) > 0 THEN
        RETURN FALSE;
    END IF;

    -- Empty scope (all arrays empty) = full delegation
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- 6. Add comments for documentation
-- ============================================================================

COMMENT ON TABLE gov_delegation_scopes IS 'Defines scope restrictions for delegations. NULL scope_id on delegation = full authority.';
COMMENT ON TABLE gov_delegation_audit IS 'Audit trail for all actions taken by deputies on behalf of delegators.';

COMMENT ON COLUMN gov_approval_delegations.scope_id IS 'Reference to scope restrictions. NULL = full delegation (all authority).';
COMMENT ON COLUMN gov_approval_delegations.status IS 'Delegation lifecycle status: pending, active, expired, revoked.';
COMMENT ON COLUMN gov_approval_delegations.expiry_warning_sent IS 'Whether 24-hour expiration warning has been sent.';

COMMENT ON COLUMN gov_delegation_scopes.application_ids IS 'Applications in scope. Empty = no application restriction.';
COMMENT ON COLUMN gov_delegation_scopes.entitlement_ids IS 'Entitlements in scope. Empty = no entitlement restriction.';
COMMENT ON COLUMN gov_delegation_scopes.role_ids IS 'Roles in scope. Empty = no role restriction.';
COMMENT ON COLUMN gov_delegation_scopes.workflow_types IS 'Workflow types in scope (access_request, certification, state_transition). Empty = no type restriction.';

COMMENT ON COLUMN gov_delegation_audit.deputy_id IS 'User who performed the action.';
COMMENT ON COLUMN gov_delegation_audit.delegator_id IS 'User on whose behalf the action was taken.';
COMMENT ON COLUMN gov_delegation_audit.action_type IS 'Type of action performed (approve_request, reject_request, etc.).';
COMMENT ON COLUMN gov_delegation_audit.work_item_id IS 'ID of the work item that was actioned.';
COMMENT ON COLUMN gov_delegation_audit.work_item_type IS 'Type of work item (access_request, certification, state_transition).';

-- ============================================================================
-- 7. Add unique constraint for concurrent deputy handling
-- ============================================================================

-- Ensure only one decision can be made per approval step.
-- This prevents race conditions when multiple deputies try to approve simultaneously.
-- First-come-first-served: the first decision to be committed wins.
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_decisions_unique_step
    ON gov_approval_decisions(request_id, step_order);

COMMENT ON INDEX idx_approval_decisions_unique_step IS
    'Ensures only one decision per approval step to handle concurrent deputy access (F053).';

-- ============================================================================
-- 8. Add is_delegable flag to entitlements (IGA edge case)
-- ============================================================================

-- Add is_delegable column to gov_entitlements
-- Only entitlements marked as delegable can be included in delegated work items.
-- This follows IGA pattern where non-delegable items are filtered out.
ALTER TABLE gov_entitlements
ADD COLUMN IF NOT EXISTS is_delegable BOOLEAN DEFAULT TRUE;

-- Add index for filtering delegable entitlements
CREATE INDEX IF NOT EXISTS idx_entitlements_delegable
    ON gov_entitlements(tenant_id, is_delegable)
    WHERE is_delegable = TRUE;

COMMENT ON COLUMN gov_entitlements.is_delegable IS
    'Whether this entitlement can be delegated. Only delegable entitlements appear in deputy work items (F053).';

-- Add is_delegable to gov_applications for application-level delegation control
ALTER TABLE gov_applications
ADD COLUMN IF NOT EXISTS is_delegable BOOLEAN DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS idx_applications_delegable
    ON gov_applications(tenant_id, is_delegable)
    WHERE is_delegable = TRUE;

COMMENT ON COLUMN gov_applications.is_delegable IS
    'Whether entitlements in this application can be delegated. Overrides entitlement-level setting (F053).';
