-- Add 'nhi' target type to gov_assignment_target_type enum.
-- This allows entitlement assignments directly to NHI identities (agents,
-- service accounts, tools) instead of requiring the target_type='user' hack.

ALTER TYPE gov_assignment_target_type ADD VALUE IF NOT EXISTS 'nhi';

-- Partial index for efficient NHI assignment lookups.
CREATE INDEX IF NOT EXISTS idx_gov_entitlement_assignments_nhi
    ON gov_entitlement_assignments(tenant_id, target_id)
    WHERE target_type = 'nhi';
