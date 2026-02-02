-- Feature 081: Custom User Attributes Enhancements
-- Migration: 081_001_custom_user_attributes_enhancements.sql
-- Adds well-known attribute tracking columns and enum data type support.

-- 1. Add is_well_known flag to track seeded well-known attributes
ALTER TABLE tenant_attribute_definitions
    ADD COLUMN is_well_known BOOLEAN NOT NULL DEFAULT false;

-- 2. Add well_known_slug for cross-tenant interoperability
ALTER TABLE tenant_attribute_definitions
    ADD COLUMN well_known_slug VARCHAR(64);

-- 3. Update data_type CHECK constraint to include 'enum'
--    Must drop and recreate because PostgreSQL doesn't support ALTER CONSTRAINT.
ALTER TABLE tenant_attribute_definitions
    DROP CONSTRAINT IF EXISTS tenant_attribute_definitions_data_type_check;

ALTER TABLE tenant_attribute_definitions
    ADD CONSTRAINT tenant_attribute_definitions_data_type_check
    CHECK (data_type IN ('string', 'number', 'boolean', 'date', 'json', 'enum'));

-- 4. Index for well-known attribute lookups
CREATE INDEX idx_tenant_attr_defs_well_known
    ON tenant_attribute_definitions(tenant_id, is_well_known)
    WHERE is_well_known = true;
