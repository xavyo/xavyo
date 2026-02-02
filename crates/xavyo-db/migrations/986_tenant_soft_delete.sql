-- F-DELETE: Add tenant soft delete support
-- Allows system admins to soft delete tenants with 30-day recovery window

-- Add soft delete columns to tenants table
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS deletion_reason TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS scheduled_purge_at TIMESTAMPTZ;

-- Index for efficient lookup of deleted tenants
CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON tenants (deleted_at) WHERE deleted_at IS NOT NULL;

-- Index for purge job to find tenants ready for permanent deletion
CREATE INDEX IF NOT EXISTS idx_tenants_scheduled_purge ON tenants (scheduled_purge_at) WHERE scheduled_purge_at IS NOT NULL;

-- Add documentation
COMMENT ON COLUMN tenants.deleted_at IS 'Timestamp when tenant was soft deleted. NULL = active tenant.';
COMMENT ON COLUMN tenants.deletion_reason IS 'Reason for deletion (for admin reference).';
COMMENT ON COLUMN tenants.scheduled_purge_at IS 'When permanent deletion will occur (typically 30 days after deleted_at).';
