-- Migration: 058_002_object_templates_edge_cases
-- Feature: F058 Object Templates - Edge Cases from IGA standards analysis
-- Description: Adds exclusive mappings, time constraints, and related features

-- ============================================================================
-- Add Exclusive and Time Constraint Columns to Template Rules
-- ============================================================================

-- Exclusive flag: If true, no other rule can target the same attribute
ALTER TABLE gov_template_rules
ADD COLUMN IF NOT EXISTS exclusive BOOLEAN NOT NULL DEFAULT false;

-- Time constraints for rule applicability
-- time_from: Rule only applies after this timestamp (relative to object creation or absolute)
ALTER TABLE gov_template_rules
ADD COLUMN IF NOT EXISTS time_from TIMESTAMPTZ;

-- time_to: Rule only applies before this timestamp
ALTER TABLE gov_template_rules
ADD COLUMN IF NOT EXISTS time_to TIMESTAMPTZ;

-- Time reference type: 'absolute' uses timestamps as-is, 'relative_to_creation' adds offset to object creation time
CREATE TYPE gov_template_time_reference AS ENUM (
    'absolute',           -- Use time_from/time_to as absolute timestamps
    'relative_to_creation' -- Interpret as offset from object creation time
);

ALTER TABLE gov_template_rules
ADD COLUMN IF NOT EXISTS time_reference gov_template_time_reference DEFAULT 'absolute';

-- ============================================================================
-- Add Constraint to Ensure Time Range is Valid
-- ============================================================================

ALTER TABLE gov_template_rules
ADD CONSTRAINT gov_template_rules_time_range_valid
CHECK (time_from IS NULL OR time_to IS NULL OR time_from < time_to);

-- ============================================================================
-- Add Index for Time-Based Rule Queries
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_gov_template_rules_time_constraints
ON gov_template_rules(template_id, time_from, time_to)
WHERE time_from IS NOT NULL OR time_to IS NOT NULL;

-- ============================================================================
-- Add Index for Exclusive Rules (for conflict detection)
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_gov_template_rules_exclusive
ON gov_template_rules(tenant_id, template_id, target_attribute)
WHERE exclusive = true;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON COLUMN gov_template_rules.exclusive IS 'If true, this rule cannot coexist with other rules targeting the same attribute. An error is raised if conflicts are detected.';
COMMENT ON COLUMN gov_template_rules.time_from IS 'Rule only applies after this timestamp. Interpretation depends on time_reference.';
COMMENT ON COLUMN gov_template_rules.time_to IS 'Rule only applies before this timestamp. Interpretation depends on time_reference.';
COMMENT ON COLUMN gov_template_rules.time_reference IS 'How to interpret time_from/time_to: absolute timestamps or relative to object creation.';
