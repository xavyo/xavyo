-- F055 Improvements Part 3: Index for flagged certifications
-- This migration must run after 055_003 to ensure new enum values are committed

-- Create partial index for flagged certifications (enables efficient queries for follow-up)
CREATE INDEX IF NOT EXISTS idx_micro_cert_flagged
ON gov_micro_certifications(tenant_id, status)
WHERE status = 'flagged_for_review';
