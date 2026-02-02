-- Migration: 066_001_provisioning_scripts.sql
-- Feature: F066 - Provisioning Scripts
-- Description: Pre/post provisioning script hooks for custom logic execution during connector operations

-- ============================================================================
-- ENUM TYPES (idempotent - only create if not exists)
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE gov_script_status AS ENUM ('draft', 'active', 'inactive');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_hook_phase AS ENUM ('before', 'after');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_script_operation_type AS ENUM ('create', 'update', 'delete', 'enable', 'disable');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_failure_policy AS ENUM ('abort', 'continue', 'retry');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_execution_status AS ENUM ('success', 'failure', 'timeout', 'skipped');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_template_category AS ENUM ('attribute_mapping', 'value_generation', 'conditional_logic', 'data_formatting', 'custom');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE gov_script_audit_action AS ENUM ('created', 'updated', 'deleted', 'activated', 'deactivated', 'rollback', 'bound', 'unbound', 'version_created');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================================
-- TABLE: gov_provisioning_scripts
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_provisioning_scripts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    current_version INTEGER NOT NULL DEFAULT 1,
    status gov_script_status NOT NULL DEFAULT 'draft',
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gov_provisioning_scripts_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT chk_gov_provisioning_scripts_version CHECK (current_version >= 1)
);

ALTER TABLE gov_provisioning_scripts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON gov_provisioning_scripts;
CREATE POLICY tenant_isolation ON gov_provisioning_scripts
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX IF NOT EXISTS idx_gov_provisioning_scripts_tenant ON gov_provisioning_scripts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_provisioning_scripts_tenant_status ON gov_provisioning_scripts(tenant_id, status);

-- ============================================================================
-- TABLE: gov_script_versions
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_script_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    script_id UUID NOT NULL REFERENCES gov_provisioning_scripts(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    script_body TEXT NOT NULL,
    change_description TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gov_script_versions_script_version UNIQUE (script_id, version_number),
    CONSTRAINT chk_gov_script_versions_version_number CHECK (version_number >= 1),
    CONSTRAINT chk_gov_script_versions_body_size CHECK (octet_length(script_body) <= 65536)
);

ALTER TABLE gov_script_versions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON gov_script_versions;
CREATE POLICY tenant_isolation ON gov_script_versions
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX IF NOT EXISTS idx_gov_script_versions_script ON gov_script_versions(script_id);
CREATE INDEX IF NOT EXISTS idx_gov_script_versions_script_version ON gov_script_versions(script_id, version_number DESC);

-- ============================================================================
-- TABLE: gov_script_hook_bindings
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_script_hook_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    script_id UUID NOT NULL REFERENCES gov_provisioning_scripts(id) ON DELETE CASCADE,
    connector_id UUID NOT NULL,
    hook_phase gov_hook_phase NOT NULL,
    operation_type gov_script_operation_type NOT NULL,
    execution_order INTEGER NOT NULL DEFAULT 0,
    failure_policy gov_failure_policy NOT NULL DEFAULT 'abort',
    max_retries INTEGER NOT NULL DEFAULT 3,
    timeout_seconds INTEGER NOT NULL DEFAULT 30,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gov_script_hook_bindings_order UNIQUE (connector_id, hook_phase, operation_type, execution_order),
    CONSTRAINT chk_gov_script_hook_bindings_execution_order CHECK (execution_order >= 0),
    CONSTRAINT chk_gov_script_hook_bindings_max_retries CHECK (max_retries >= 0 AND max_retries <= 10),
    CONSTRAINT chk_gov_script_hook_bindings_timeout CHECK (timeout_seconds >= 1 AND timeout_seconds <= 300)
);

ALTER TABLE gov_script_hook_bindings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON gov_script_hook_bindings;
CREATE POLICY tenant_isolation ON gov_script_hook_bindings
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX IF NOT EXISTS idx_gov_script_hook_bindings_tenant ON gov_script_hook_bindings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_script_hook_bindings_script ON gov_script_hook_bindings(script_id);
CREATE INDEX IF NOT EXISTS idx_gov_script_hook_bindings_connector ON gov_script_hook_bindings(connector_id);
CREATE INDEX IF NOT EXISTS idx_gov_script_hook_bindings_connector_phase ON gov_script_hook_bindings(connector_id, hook_phase, operation_type, execution_order);

-- ============================================================================
-- TABLE: gov_script_execution_logs
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_script_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    script_id UUID REFERENCES gov_provisioning_scripts(id) ON DELETE SET NULL,
    binding_id UUID REFERENCES gov_script_hook_bindings(id) ON DELETE SET NULL,
    connector_id UUID NOT NULL,
    script_version INTEGER NOT NULL,
    hook_phase gov_hook_phase NOT NULL,
    operation_type gov_script_operation_type NOT NULL,
    execution_status gov_execution_status NOT NULL,
    input_context JSONB,
    output_result JSONB,
    error_message TEXT,
    duration_ms BIGINT NOT NULL,
    dry_run BOOLEAN NOT NULL DEFAULT false,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_gov_script_execution_logs_duration CHECK (duration_ms >= 0),
    CONSTRAINT chk_gov_script_execution_logs_version CHECK (script_version >= 1)
);

ALTER TABLE gov_script_execution_logs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON gov_script_execution_logs;
CREATE POLICY tenant_isolation ON gov_script_execution_logs
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX IF NOT EXISTS idx_gov_script_execution_logs_tenant_script ON gov_script_execution_logs(tenant_id, script_id, executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_gov_script_execution_logs_tenant_connector ON gov_script_execution_logs(tenant_id, connector_id, executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_gov_script_execution_logs_tenant_status ON gov_script_execution_logs(tenant_id, execution_status);
CREATE INDEX IF NOT EXISTS idx_gov_script_execution_logs_executed ON gov_script_execution_logs(tenant_id, executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_gov_script_execution_logs_dry_run ON gov_script_execution_logs(tenant_id, dry_run) WHERE dry_run = true;

-- ============================================================================
-- TABLE: gov_script_templates
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_script_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category gov_template_category NOT NULL,
    template_body TEXT NOT NULL,
    placeholder_annotations JSONB,
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gov_script_templates_tenant_name UNIQUE (tenant_id, name)
);

ALTER TABLE gov_script_templates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON gov_script_templates;
CREATE POLICY tenant_isolation ON gov_script_templates
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX IF NOT EXISTS idx_gov_script_templates_tenant ON gov_script_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_script_templates_tenant_category ON gov_script_templates(tenant_id, category);
CREATE INDEX IF NOT EXISTS idx_gov_script_templates_system ON gov_script_templates(tenant_id, is_system) WHERE is_system = true;

-- ============================================================================
-- TABLE: gov_script_audit_events
-- ============================================================================

CREATE TABLE IF NOT EXISTS gov_script_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    script_id UUID,
    action gov_script_audit_action NOT NULL,
    actor_id UUID NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE gov_script_audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON gov_script_audit_events;
CREATE POLICY tenant_isolation ON gov_script_audit_events
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

CREATE INDEX IF NOT EXISTS idx_gov_script_audit_events_tenant_script ON gov_script_audit_events(tenant_id, script_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gov_script_audit_events_tenant_action ON gov_script_audit_events(tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_gov_script_audit_events_tenant_created ON gov_script_audit_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gov_script_audit_events_actor ON gov_script_audit_events(tenant_id, actor_id);
