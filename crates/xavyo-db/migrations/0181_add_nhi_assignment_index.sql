-- Partial index for efficient NHI assignment lookups.
-- Split from migration 0180 because PostgreSQL cannot use a newly added
-- enum value in the same transaction that added it.

CREATE INDEX IF NOT EXISTS idx_gov_entitlement_assignments_nhi
    ON gov_entitlement_assignments(tenant_id, target_id)
    WHERE target_type = 'nhi';
