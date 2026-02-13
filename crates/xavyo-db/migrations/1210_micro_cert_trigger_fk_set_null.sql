-- Fix: Allow deleting trigger rules that have associated certifications.
-- Change trigger_rule_id from NOT NULL + ON DELETE RESTRICT to nullable + ON DELETE SET NULL.

-- Step 1: Make trigger_rule_id nullable
ALTER TABLE gov_micro_certifications ALTER COLUMN trigger_rule_id DROP NOT NULL;

-- Step 2: Drop the existing FK constraint and recreate with ON DELETE SET NULL
ALTER TABLE gov_micro_certifications
    DROP CONSTRAINT IF EXISTS gov_micro_certifications_trigger_rule_id_fkey;

ALTER TABLE gov_micro_certifications
    ADD CONSTRAINT gov_micro_certifications_trigger_rule_id_fkey
    FOREIGN KEY (trigger_rule_id) REFERENCES gov_micro_cert_triggers(id) ON DELETE SET NULL;
