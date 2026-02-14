-- Migration: 088_004_gov_role_entitlements_add_role_id
-- Feature: F088 - Business Role Hierarchy Model
-- Description: Add role_id FK column to gov_role_entitlements for structured role references

-- Add role_id column to gov_role_entitlements
-- This allows existing string-based role_name mappings to coexist with new UUID-based gov_roles references
ALTER TABLE gov_role_entitlements
ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES gov_roles(id) ON DELETE SET NULL;

-- Index for lookups by role_id
CREATE INDEX IF NOT EXISTS idx_gov_role_entitlements_role_id
ON gov_role_entitlements(role_id)
WHERE role_id IS NOT NULL;

-- Comments for documentation
COMMENT ON COLUMN gov_role_entitlements.role_id IS 'Optional FK to gov_roles entity for structured role hierarchy support (F088)';
