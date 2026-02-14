-- Migration: 025_delegated_admin.sql
-- Feature: F029 - Delegated Administration
-- Description: Create tables for granular admin permissions with scopes

-- ============================================================================
-- Part 1: Admin Permissions table (system-defined permissions)
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Constraints
    CONSTRAINT chk_permission_code_format CHECK (code ~ '^[a-z]+:[a-z_]+$'),
    CONSTRAINT chk_permission_category CHECK (category IN ('users', 'groups', 'settings', 'security', 'audit', 'branding'))
);

-- Index for category lookup
CREATE INDEX IF NOT EXISTS idx_admin_permissions_category ON admin_permissions(category);

-- ============================================================================
-- Part 2: Admin Role Templates table
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_role_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL for system templates
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Unique name per tenant (or globally for system templates)
    CONSTRAINT uq_role_template_name UNIQUE NULLS NOT DISTINCT (tenant_id, name)
);

-- Indexes for role templates
CREATE INDEX IF NOT EXISTS idx_admin_role_templates_tenant ON admin_role_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_role_templates_system ON admin_role_templates(is_system) WHERE is_system = true;

-- ============================================================================
-- Part 3: Admin Role Template Permissions (M2M)
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_role_template_permissions (
    template_id UUID NOT NULL REFERENCES admin_role_templates(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES admin_permissions(id) ON DELETE CASCADE,

    PRIMARY KEY (template_id, permission_id)
);

-- Index for permission lookup
CREATE INDEX IF NOT EXISTS idx_role_template_permissions_permission ON admin_role_template_permissions(permission_id);

-- ============================================================================
-- Part 4: User Admin Assignments table
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_admin_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES admin_role_templates(id) ON DELETE CASCADE,
    scope_type VARCHAR(20),
    scope_value TEXT[],
    assigned_by UUID NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT chk_scope_type CHECK (scope_type IS NULL OR scope_type IN ('group', 'department', 'custom')),
    CONSTRAINT chk_scope_consistency CHECK (
        (scope_type IS NULL AND scope_value IS NULL) OR
        (scope_type IS NOT NULL AND scope_value IS NOT NULL AND array_length(scope_value, 1) > 0)
    )
);

-- Indexes for user admin assignments
CREATE INDEX IF NOT EXISTS idx_user_admin_assignments_user
    ON user_admin_assignments(tenant_id, user_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_admin_assignments_template
    ON user_admin_assignments(tenant_id, template_id);
CREATE INDEX IF NOT EXISTS idx_user_admin_assignments_expires
    ON user_admin_assignments(expires_at)
    WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_user_admin_assignments_active
    ON user_admin_assignments(tenant_id, user_id, template_id)
    WHERE revoked_at IS NULL;

-- ============================================================================
-- Part 5: Admin Audit Log table
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    admin_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    old_value JSONB,
    new_value JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Constraints
    CONSTRAINT chk_audit_action CHECK (action IN ('create', 'update', 'delete', 'assign', 'revoke', 'access_denied')),
    CONSTRAINT chk_audit_resource_type CHECK (resource_type IN ('user', 'template', 'assignment', 'permission'))
);

-- Indexes for admin audit log
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_tenant_time
    ON admin_audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_admin
    ON admin_audit_log(tenant_id, admin_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_resource
    ON admin_audit_log(tenant_id, resource_type, resource_id);

-- ============================================================================
-- Part 6: Row Level Security
-- ============================================================================

-- Enable RLS on tables that need tenant isolation
ALTER TABLE admin_role_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_admin_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_log ENABLE ROW LEVEL SECURITY;

-- Note: admin_permissions does NOT have RLS (global, same for all tenants)

-- RLS for admin_role_templates (system templates visible to all)
DROP POLICY IF EXISTS tenant_isolation_role_templates_select ON admin_role_templates;
CREATE POLICY tenant_isolation_role_templates_select ON admin_role_templates
    FOR SELECT
    USING (
        tenant_id IS NULL  -- System templates visible to all
        OR tenant_id = current_setting('app.current_tenant', true)::uuid
    );

DROP POLICY IF EXISTS tenant_isolation_role_templates_insert ON admin_role_templates;
CREATE POLICY tenant_isolation_role_templates_insert ON admin_role_templates
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_role_templates_update ON admin_role_templates;
CREATE POLICY tenant_isolation_role_templates_update ON admin_role_templates
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_role_templates_delete ON admin_role_templates;
CREATE POLICY tenant_isolation_role_templates_delete ON admin_role_templates
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for user_admin_assignments (standard tenant isolation)
DROP POLICY IF EXISTS tenant_isolation_assignments_select ON user_admin_assignments;
CREATE POLICY tenant_isolation_assignments_select ON user_admin_assignments
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_assignments_insert ON user_admin_assignments;
CREATE POLICY tenant_isolation_assignments_insert ON user_admin_assignments
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_assignments_update ON user_admin_assignments;
CREATE POLICY tenant_isolation_assignments_update ON user_admin_assignments
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_assignments_delete ON user_admin_assignments;
CREATE POLICY tenant_isolation_assignments_delete ON user_admin_assignments
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for admin_audit_log (standard tenant isolation)
DROP POLICY IF EXISTS tenant_isolation_audit_log_select ON admin_audit_log;
CREATE POLICY tenant_isolation_audit_log_select ON admin_audit_log
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_audit_log_insert ON admin_audit_log;
CREATE POLICY tenant_isolation_audit_log_insert ON admin_audit_log
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 7: Seed data - System permissions
-- ============================================================================

INSERT INTO admin_permissions (code, name, description, category) VALUES
    -- Users category
    ('users:read', 'View Users', 'View user list and user details', 'users'),
    ('users:create', 'Create Users', 'Create new user accounts', 'users'),
    ('users:update', 'Update Users', 'Update user information', 'users'),
    ('users:delete', 'Delete Users', 'Delete user accounts', 'users'),
    -- Groups category
    ('groups:read', 'View Groups', 'View group list and group details', 'groups'),
    ('groups:create', 'Create Groups', 'Create new groups', 'groups'),
    ('groups:update', 'Update Groups', 'Update group information', 'groups'),
    ('groups:delete', 'Delete Groups', 'Delete groups', 'groups'),
    ('groups:manage', 'Manage Group Members', 'Add or remove members from groups', 'groups'),
    -- Settings category
    ('settings:read', 'View Settings', 'View tenant settings', 'settings'),
    ('settings:update', 'Update Settings', 'Modify tenant settings', 'settings'),
    -- Security category
    ('security:read', 'View Security Settings', 'View security configurations', 'security'),
    ('security:update', 'Update Security Settings', 'Modify security configurations', 'security'),
    ('security:manage', 'Manage Security Policies', 'Configure security policies and rules', 'security'),
    -- Audit category
    ('audit:read', 'View Audit Logs', 'View audit trail and logs', 'audit'),
    -- Branding category
    ('branding:read', 'View Branding', 'View branding settings', 'branding'),
    ('branding:update', 'Update Branding', 'Modify branding settings', 'branding')
ON CONFLICT (code) DO NOTHING;

-- ============================================================================
-- Part 8: Seed data - System role templates
-- ============================================================================

-- Insert system templates (tenant_id = NULL, is_system = true)
INSERT INTO admin_role_templates (id, tenant_id, name, description, is_system, created_at, updated_at)
VALUES
    ('00000000-0000-0000-0001-000000000001', NULL, 'User Admin', 'Full user management capabilities', true, now(), now()),
    ('00000000-0000-0000-0001-000000000002', NULL, 'Security Admin', 'Security settings and audit access', true, now(), now()),
    ('00000000-0000-0000-0001-000000000003', NULL, 'Read Only', 'View-only access to all resources', true, now(), now())
ON CONFLICT DO NOTHING;

-- Link system templates to permissions
-- User Admin: all user permissions (users:*)
INSERT INTO admin_role_template_permissions (template_id, permission_id)
SELECT '00000000-0000-0000-0001-000000000001', id FROM admin_permissions WHERE category = 'users'
ON CONFLICT DO NOTHING;

-- Security Admin: all security permissions + audit:read
INSERT INTO admin_role_template_permissions (template_id, permission_id)
SELECT '00000000-0000-0000-0001-000000000002', id FROM admin_permissions WHERE category = 'security'
ON CONFLICT DO NOTHING;
INSERT INTO admin_role_template_permissions (template_id, permission_id)
SELECT '00000000-0000-0000-0001-000000000002', id FROM admin_permissions WHERE code = 'audit:read'
ON CONFLICT DO NOTHING;

-- Read Only: all read permissions
INSERT INTO admin_role_template_permissions (template_id, permission_id)
SELECT '00000000-0000-0000-0001-000000000003', id FROM admin_permissions WHERE code LIKE '%:read'
ON CONFLICT DO NOTHING;

-- ============================================================================
-- Part 9: Comments for documentation
-- ============================================================================

-- Tables
COMMENT ON TABLE admin_permissions IS 'System-defined granular permissions for delegated administration';
COMMENT ON TABLE admin_role_templates IS 'Role templates that group permissions for assignment to users';
COMMENT ON TABLE admin_role_template_permissions IS 'Many-to-many relationship between templates and permissions';
COMMENT ON TABLE user_admin_assignments IS 'Links users to role templates with optional scope restrictions';
COMMENT ON TABLE admin_audit_log IS 'Audit trail of all administrative actions';

-- admin_permissions columns
COMMENT ON COLUMN admin_permissions.code IS 'Unique permission code in format category:action (e.g., users:read)';
COMMENT ON COLUMN admin_permissions.category IS 'Permission category: users, groups, settings, security, audit, branding';

-- admin_role_templates columns
COMMENT ON COLUMN admin_role_templates.tenant_id IS 'NULL for system templates, tenant UUID for custom templates';
COMMENT ON COLUMN admin_role_templates.is_system IS 'True for immutable system templates that cannot be deleted';

-- user_admin_assignments columns
COMMENT ON COLUMN user_admin_assignments.scope_type IS 'Type of scope restriction: group, department, or custom';
COMMENT ON COLUMN user_admin_assignments.scope_value IS 'Array of scope values (group IDs, department names, etc.)';
COMMENT ON COLUMN user_admin_assignments.assigned_by IS 'User ID of the super admin who made the assignment';
COMMENT ON COLUMN user_admin_assignments.expires_at IS 'Optional expiration date for automatic permission revocation';
COMMENT ON COLUMN user_admin_assignments.revoked_at IS 'Timestamp when assignment was manually revoked (soft delete)';

-- admin_audit_log columns
COMMENT ON COLUMN admin_audit_log.action IS 'Action type: create, update, delete, assign, revoke, access_denied';
COMMENT ON COLUMN admin_audit_log.resource_type IS 'Resource type: user, template, assignment, permission';
COMMENT ON COLUMN admin_audit_log.old_value IS 'Previous state in JSON format (for updates and deletes)';
COMMENT ON COLUMN admin_audit_log.new_value IS 'New state in JSON format (for creates and updates)';
