-- F038: Birthright Access Policies - Add Evaluation Mode
-- This migration adds evaluation_mode column for first-match vs all-match policy evaluation.

-- ============================================================================
-- ENUMS
-- ============================================================================

-- Evaluation mode for birthright policies
CREATE TYPE evaluation_mode AS ENUM ('first_match', 'all_match');

-- ============================================================================
-- ALTER GOV_BIRTHRIGHT_POLICIES TABLE
-- ============================================================================

-- Add evaluation_mode column with default to all_match (backward compatible)
ALTER TABLE gov_birthright_policies
ADD COLUMN IF NOT EXISTS evaluation_mode evaluation_mode NOT NULL DEFAULT 'all_match';

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON COLUMN gov_birthright_policies.evaluation_mode IS 'Evaluation mode: first_match stops at first matching policy, all_match applies all matching policies';
