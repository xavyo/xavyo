-- Fix admin_audit_log CHECK constraints to include all resource types and actions
-- used by the application code. Missing values cause INSERT failures (500 errors).
-- Also fix RLS policies: consolidate old per-operation policies into single NULLIF
-- pattern policy. The old INSERT policy used bare ::uuid cast which fails when
-- app.current_tenant is empty string.

-- Drop old constraints
ALTER TABLE admin_audit_log DROP CONSTRAINT IF EXISTS chk_audit_action;
ALTER TABLE admin_audit_log DROP CONSTRAINT IF EXISTS chk_audit_resource_type;

-- Recreate with all used values
ALTER TABLE admin_audit_log ADD CONSTRAINT chk_audit_action CHECK (
    action IN (
        'create', 'update', 'delete', 'assign', 'revoke',
        'access_denied', 'move'
    )
);

ALTER TABLE admin_audit_log ADD CONSTRAINT chk_audit_resource_type CHECK (
    resource_type IN (
        'user', 'template', 'assignment', 'permission', 'tenant',
        'api_key', 'oauth_client', 'mfa_policy', 'session_policy', 'password_policy',
        'tenant_settings', 'tenant_plan', 'admin_invitation',
        'gov_role', 'gov_role_inheritance_block', 'gov_role_entitlement'
    )
);

-- Fix RLS: drop old per-operation policies and consolidate into single NULLIF policy
DROP POLICY IF EXISTS tenant_isolation_audit_log_select ON admin_audit_log;
DROP POLICY IF EXISTS tenant_isolation_audit_log_insert ON admin_audit_log;
DROP POLICY IF EXISTS tenant_isolation_policy ON admin_audit_log;
CREATE POLICY tenant_isolation_policy ON admin_audit_log
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
