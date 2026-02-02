-- F-SUSPEND: Add tenant suspension support
-- Allows system admins to suspend tenants to prevent abuse

-- Add suspension columns to tenants table
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS suspension_reason TEXT;

-- Add index for efficient lookup of suspended tenants
CREATE INDEX IF NOT EXISTS idx_tenants_suspended_at ON tenants (suspended_at) WHERE suspended_at IS NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN tenants.suspended_at IS 'Timestamp when tenant was suspended. NULL = active tenant.';
COMMENT ON COLUMN tenants.suspension_reason IS 'Reason for suspension (for admin reference).';
