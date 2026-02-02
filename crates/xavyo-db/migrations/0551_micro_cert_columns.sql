-- F055 Improvements Part 1: Add new columns for delegation
-- Note: New enum values are added in 055_003 (separate migration required
-- because ALTER TYPE ADD VALUE cannot be in a transaction with statements
-- that use the new value).

-- =============================================================================
-- ADD DELEGATE_TO FIELD TO CERTIFICATIONS
-- =============================================================================

-- Add column for tracking delegation chain
ALTER TABLE gov_micro_certifications
ADD COLUMN IF NOT EXISTS delegated_by_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Add column for original reviewer (before any delegation)
ALTER TABLE gov_micro_certifications
ADD COLUMN IF NOT EXISTS original_reviewer_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Add column for delegation comment
ALTER TABLE gov_micro_certifications
ADD COLUMN IF NOT EXISTS delegation_comment TEXT;
