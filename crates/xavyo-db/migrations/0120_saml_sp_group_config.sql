-- Add group configuration fields to saml_service_providers
-- Feature: F-039 SAML Group Assertions

-- Add group attribute configuration columns
ALTER TABLE saml_service_providers
ADD COLUMN IF NOT EXISTS group_attribute_name VARCHAR(256),
ADD COLUMN IF NOT EXISTS group_value_format VARCHAR(20) NOT NULL DEFAULT 'name',
ADD COLUMN IF NOT EXISTS group_filter JSONB,
ADD COLUMN IF NOT EXISTS include_groups BOOLEAN NOT NULL DEFAULT TRUE,
ADD COLUMN IF NOT EXISTS omit_empty_groups BOOLEAN NOT NULL DEFAULT TRUE,
ADD COLUMN IF NOT EXISTS group_dn_base VARCHAR(512);

-- Add constraint for group_value_format
-- Valid values: 'name', 'id', 'dn'
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'check_group_value_format'
    ) THEN
        ALTER TABLE saml_service_providers
        ADD CONSTRAINT check_group_value_format
        CHECK (group_value_format IN ('name', 'id', 'dn'));
    END IF;
END $$;

-- Add comment for documentation
COMMENT ON COLUMN saml_service_providers.group_attribute_name IS 'Custom SAML attribute name for groups (default: groups)';
COMMENT ON COLUMN saml_service_providers.group_value_format IS 'How to format group values: name (display_name), id (UUID), dn (Distinguished Name)';
COMMENT ON COLUMN saml_service_providers.group_filter IS 'JSON filter config: {filter_type: "none"|"pattern"|"allowlist", patterns: [], allowlist: []}';
COMMENT ON COLUMN saml_service_providers.include_groups IS 'Whether to include groups in SAML assertions';
COMMENT ON COLUMN saml_service_providers.omit_empty_groups IS 'Whether to omit groups attribute when user has no groups';
COMMENT ON COLUMN saml_service_providers.group_dn_base IS 'Base DN for DN format (e.g., ou=Groups,dc=example,dc=com)';
