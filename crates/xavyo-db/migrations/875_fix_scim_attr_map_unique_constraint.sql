-- Migration: Fix scim_target_attribute_mappings unique constraint
-- Feature: F087 - SCIM 2.0 Outbound Provisioning Client
-- Description: The unique constraint was on (target_id, source_field, resource_type) but
--              we need to allow the same source field to map to multiple SCIM paths
--              (e.g., email -> userName AND email -> emails[0].value).
--              Fix to (target_id, target_scim_path, resource_type) instead.

-- Drop the old constraint
ALTER TABLE scim_target_attribute_mappings
DROP CONSTRAINT IF EXISTS scim_attr_map_unique;

-- Add the corrected constraint
-- Each SCIM path can only be mapped once per target/resource_type,
-- but the same source field can be used for multiple SCIM paths.
ALTER TABLE scim_target_attribute_mappings
ADD CONSTRAINT scim_attr_map_unique UNIQUE (target_id, target_scim_path, resource_type);

COMMENT ON CONSTRAINT scim_attr_map_unique ON scim_target_attribute_mappings
    IS 'Each SCIM path can only be mapped once per target/resource_type';
