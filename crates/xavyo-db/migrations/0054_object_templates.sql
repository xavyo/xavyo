-- Migration: 058_001_object_templates
-- Feature: F058 Object Templates
-- Description: Creates tables for object templates with rules, scopes, versions, and merge policies

-- ============================================================================
-- Enum Types
-- ============================================================================

-- Object types templates can target
CREATE TYPE gov_template_object_type AS ENUM (
    'user',
    'role',
    'entitlement',
    'application'
);

-- Template lifecycle status
CREATE TYPE gov_object_template_status AS ENUM (
    'draft',      -- Being configured, not applied
    'active',     -- Applied to matching objects
    'disabled'    -- Temporarily disabled
);

-- Rule types
CREATE TYPE gov_template_rule_type AS ENUM (
    'default',        -- Static default value
    'computed',       -- Computed from expression
    'validation',     -- Validation check
    'normalization'   -- Transform/normalize value
);

-- Mapping strength
CREATE TYPE gov_template_strength AS ENUM (
    'strong',   -- Always enforced, cannot be overridden
    'normal',   -- Applied unless user explicitly sets different value
    'weak'      -- Only applied if target is empty
);

-- Scope types
CREATE TYPE gov_template_scope_type AS ENUM (
    'global',       -- Applies to all objects of type
    'organization', -- Applies to specific org
    'category',     -- Applies to object category/type
    'condition'     -- Applies when condition matches
);

-- Merge strategies
CREATE TYPE gov_template_merge_strategy AS ENUM (
    'source_precedence',   -- Ordered source priority
    'timestamp_wins',      -- Most recent value
    'concatenate_unique',  -- Combine unique values
    'first_wins',          -- First non-null preserved
    'manual_only'          -- Only accept manual changes
);

-- Null handling in merge
CREATE TYPE gov_template_null_handling AS ENUM (
    'merge',          -- Null = no value to merge
    'preserve_empty'  -- Null = explicit empty
);

-- Operation types for application events
CREATE TYPE gov_template_operation AS ENUM (
    'create',
    'update'
);

-- Template change event types
CREATE TYPE gov_template_event_type AS ENUM (
    'created',
    'updated',
    'activated',
    'disabled',
    'deleted',
    'version_created',
    'rule_added',
    'rule_updated',
    'rule_removed',
    'scope_added',
    'scope_removed',
    'merge_policy_added',
    'merge_policy_updated',
    'merge_policy_removed'
);

-- ============================================================================
-- Object Templates Table (Primary Entity)
-- ============================================================================

CREATE TABLE gov_object_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    object_type gov_template_object_type NOT NULL,
    status gov_object_template_status NOT NULL DEFAULT 'draft',
    priority INTEGER NOT NULL DEFAULT 100,
    parent_template_id UUID REFERENCES gov_object_templates(id) ON DELETE SET NULL,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name per tenant
    CONSTRAINT gov_object_templates_unique_name UNIQUE (tenant_id, name),
    -- No self-reference
    CONSTRAINT gov_object_templates_no_self_parent CHECK (parent_template_id != id),
    -- Priority range 1-1000
    CONSTRAINT gov_object_templates_priority_range CHECK (priority >= 1 AND priority <= 1000)
);

-- Enable RLS
ALTER TABLE gov_object_templates ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_object_templates_tenant_isolation ON gov_object_templates
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_object_templates_tenant_status ON gov_object_templates(tenant_id, status);
CREATE INDEX idx_gov_object_templates_tenant_type ON gov_object_templates(tenant_id, object_type);
CREATE INDEX idx_gov_object_templates_tenant_priority ON gov_object_templates(tenant_id, priority);
CREATE INDEX idx_gov_object_templates_parent ON gov_object_templates(parent_template_id);

-- ============================================================================
-- Template Rules Table
-- ============================================================================

CREATE TABLE gov_template_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES gov_object_templates(id) ON DELETE CASCADE,
    rule_type gov_template_rule_type NOT NULL,
    target_attribute VARCHAR(255) NOT NULL,
    expression TEXT NOT NULL,
    strength gov_template_strength NOT NULL DEFAULT 'normal',
    authoritative BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 100,
    condition TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Priority range 1-1000
    CONSTRAINT gov_template_rules_priority_range CHECK (priority >= 1 AND priority <= 1000)
);

-- Enable RLS
ALTER TABLE gov_template_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_template_rules_tenant_isolation ON gov_template_rules
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_template_rules_template ON gov_template_rules(template_id);
CREATE INDEX idx_gov_template_rules_target ON gov_template_rules(tenant_id, target_attribute);
CREATE INDEX idx_gov_template_rules_type ON gov_template_rules(template_id, rule_type);
CREATE INDEX idx_gov_template_rules_priority ON gov_template_rules(template_id, priority);

-- ============================================================================
-- Template Scopes Table
-- ============================================================================

CREATE TABLE gov_template_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES gov_object_templates(id) ON DELETE CASCADE,
    scope_type gov_template_scope_type NOT NULL,
    scope_value VARCHAR(500),
    condition TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE gov_template_scopes ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_template_scopes_tenant_isolation ON gov_template_scopes
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_template_scopes_template ON gov_template_scopes(template_id);
CREATE INDEX idx_gov_template_scopes_type_value ON gov_template_scopes(tenant_id, scope_type, scope_value);

-- ============================================================================
-- Template Versions Table (Immutable Snapshots)
-- ============================================================================

CREATE TABLE gov_template_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES gov_object_templates(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    rules_snapshot JSONB NOT NULL,
    scopes_snapshot JSONB NOT NULL,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique version per template
    CONSTRAINT gov_template_versions_unique UNIQUE (template_id, version_number),
    -- Version must be positive
    CONSTRAINT gov_template_versions_positive CHECK (version_number > 0)
);

-- Enable RLS
ALTER TABLE gov_template_versions ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_template_versions_tenant_isolation ON gov_template_versions
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_template_versions_template ON gov_template_versions(template_id);
CREATE INDEX idx_gov_template_versions_number ON gov_template_versions(template_id, version_number DESC);

-- ============================================================================
-- Template Merge Policies Table
-- ============================================================================

CREATE TABLE gov_template_merge_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES gov_object_templates(id) ON DELETE CASCADE,
    attribute VARCHAR(255) NOT NULL,
    strategy gov_template_merge_strategy NOT NULL,
    source_precedence JSONB,
    null_handling gov_template_null_handling NOT NULL DEFAULT 'merge',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique policy per attribute per template
    CONSTRAINT gov_template_merge_policies_unique UNIQUE (template_id, attribute)
);

-- Enable RLS
ALTER TABLE gov_template_merge_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_template_merge_policies_tenant_isolation ON gov_template_merge_policies
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_template_merge_policies_template ON gov_template_merge_policies(template_id);
CREATE INDEX idx_gov_template_merge_policies_attribute ON gov_template_merge_policies(tenant_id, attribute);

-- ============================================================================
-- Template Exclusions Table (Exclude parent rules in child templates)
-- ============================================================================

CREATE TABLE gov_template_exclusions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES gov_object_templates(id) ON DELETE CASCADE,
    excluded_rule_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique exclusion per rule per template
    CONSTRAINT gov_template_exclusions_unique UNIQUE (template_id, excluded_rule_id)
);

-- Enable RLS
ALTER TABLE gov_template_exclusions ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_template_exclusions_tenant_isolation ON gov_template_exclusions
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_template_exclusions_template ON gov_template_exclusions(template_id);
CREATE INDEX idx_gov_template_exclusions_rule ON gov_template_exclusions(excluded_rule_id);

-- ============================================================================
-- Template Application Events Table (Audit Trail)
-- ============================================================================

CREATE TABLE gov_template_application_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID REFERENCES gov_object_templates(id) ON DELETE SET NULL,
    template_version_id UUID REFERENCES gov_template_versions(id) ON DELETE SET NULL,
    object_type gov_template_object_type NOT NULL,
    object_id UUID NOT NULL,
    operation gov_template_operation NOT NULL,
    rules_applied JSONB NOT NULL,
    changes_made JSONB NOT NULL,
    validation_errors JSONB,
    actor_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE gov_template_application_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_template_application_events_tenant_isolation ON gov_template_application_events
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_template_app_events_tenant_time ON gov_template_application_events(tenant_id, created_at DESC);
CREATE INDEX idx_gov_template_app_events_object ON gov_template_application_events(tenant_id, object_type, object_id);
CREATE INDEX idx_gov_template_app_events_template ON gov_template_application_events(template_id);

-- ============================================================================
-- Template Events Table (Template Modification Audit)
-- ============================================================================

CREATE TABLE gov_template_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_id UUID REFERENCES gov_object_templates(id) ON DELETE SET NULL,
    event_type gov_template_event_type NOT NULL,
    actor_id UUID,
    changes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE gov_template_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_template_events_tenant_isolation ON gov_template_events
    USING (
        tenant_id::text = NULLIF(current_setting('app.current_tenant', true), '')
        OR current_setting('app.current_tenant', true) IS NULL
        OR current_setting('app.current_tenant', true) = ''
    );

-- Indexes
CREATE INDEX idx_gov_template_events_tenant_time ON gov_template_events(tenant_id, created_at DESC);
CREATE INDEX idx_gov_template_events_template ON gov_template_events(template_id);
CREATE INDEX idx_gov_template_events_type ON gov_template_events(tenant_id, event_type);

-- ============================================================================
-- Triggers for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_gov_template_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_gov_object_templates_updated_at
    BEFORE UPDATE ON gov_object_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_template_updated_at();

CREATE TRIGGER trigger_gov_template_rules_updated_at
    BEFORE UPDATE ON gov_template_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_template_updated_at();

CREATE TRIGGER trigger_gov_template_merge_policies_updated_at
    BEFORE UPDATE ON gov_template_merge_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_template_updated_at();
