-- Migration: F108 - Add NHI governance fields to ai_agents
-- Purpose: Cross-pollinate governance capabilities from service accounts to AI agents

-- Add backup owner for governance continuity
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS backup_owner_id UUID REFERENCES users(id);

-- Add credential rotation tracking
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS rotation_interval_days INTEGER;
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS last_rotation_at TIMESTAMPTZ;

-- Add inactivity detection
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS inactivity_threshold_days INTEGER DEFAULT 90;
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS grace_period_ends_at TIMESTAMPTZ;
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS suspension_reason TEXT;

-- Add computed risk score (0-100)
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0
    CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100));

-- Add certification tracking
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS next_certification_at TIMESTAMPTZ;
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS last_certified_at TIMESTAMPTZ;
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS last_certified_by UUID REFERENCES users(id);

-- Index for certification queries
CREATE INDEX IF NOT EXISTS idx_ai_agents_next_certification
ON ai_agents(tenant_id, next_certification_at)
WHERE next_certification_at IS NOT NULL;

-- Index for inactivity queries
CREATE INDEX IF NOT EXISTS idx_ai_agents_inactivity
ON ai_agents(tenant_id, last_activity_at, inactivity_threshold_days)
WHERE inactivity_threshold_days IS NOT NULL;

-- Index for backup owner lookups
CREATE INDEX IF NOT EXISTS idx_ai_agents_backup_owner
ON ai_agents(backup_owner_id)
WHERE backup_owner_id IS NOT NULL;

-- Comments for documentation
COMMENT ON COLUMN ai_agents.backup_owner_id IS 'F108: Backup owner for governance continuity when primary owner unavailable';
COMMENT ON COLUMN ai_agents.rotation_interval_days IS 'F108: Number of days between required credential rotations';
COMMENT ON COLUMN ai_agents.last_rotation_at IS 'F108: Timestamp of last credential rotation';
COMMENT ON COLUMN ai_agents.inactivity_threshold_days IS 'F108: Days of inactivity before agent enters grace period';
COMMENT ON COLUMN ai_agents.grace_period_ends_at IS 'F108: When grace period expires and agent will be suspended';
COMMENT ON COLUMN ai_agents.suspension_reason IS 'F108: Reason for suspension (Inactive, CertificationRevoked, Emergency, Manual)';
COMMENT ON COLUMN ai_agents.risk_score IS 'F108: Unified risk score 0-100 for governance dashboard';
COMMENT ON COLUMN ai_agents.next_certification_at IS 'F108: When next certification review is due';
COMMENT ON COLUMN ai_agents.last_certified_at IS 'F108: Timestamp of last certification';
COMMENT ON COLUMN ai_agents.last_certified_by IS 'F108: User who performed last certification';
