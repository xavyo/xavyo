-- Migration: Fix RLS policies to handle empty tenant context
-- Description: Updates all RLS policies to use NULLIF to prevent UUID cast errors
--              when tenant context is cleared (empty string instead of NULL)

-- ============================================================================
-- users table (002_create_users_with_rls.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON users;
CREATE POLICY tenant_isolation_policy ON users
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- refresh_tokens table (004_create_refresh_tokens.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON refresh_tokens;
CREATE POLICY tenant_isolation_policy ON refresh_tokens
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- password_reset_tokens table (005_create_password_reset_tokens.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON password_reset_tokens;
CREATE POLICY tenant_isolation_policy ON password_reset_tokens
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- email_verification_tokens table (006_create_email_verification_tokens.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON email_verification_tokens;
CREATE POLICY tenant_isolation_policy ON email_verification_tokens
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- oauth_clients table (009_create_oauth_clients.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON oauth_clients;
CREATE POLICY tenant_isolation_policy ON oauth_clients
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- authorization_codes table (010_create_authorization_codes.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON authorization_codes;
CREATE POLICY tenant_isolation_policy ON authorization_codes
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- oauth_refresh_tokens table (011_create_oauth_refresh_tokens.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON oauth_refresh_tokens;
CREATE POLICY tenant_isolation_policy ON oauth_refresh_tokens
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- social_connections table (012_create_social_connections.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON social_connections;
CREATE POLICY tenant_isolation_policy ON social_connections
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- tenant_social_providers table (013_create_tenant_social_providers.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_social_providers;
CREATE POLICY tenant_isolation_policy ON tenant_social_providers
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- saml_service_providers table (014_create_saml_service_providers.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON saml_service_providers;
DROP POLICY IF EXISTS tenant_isolation ON saml_service_providers;
CREATE POLICY tenant_isolation_policy ON saml_service_providers
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_idp_certificates;
DROP POLICY IF EXISTS tenant_isolation ON tenant_idp_certificates;
CREATE POLICY tenant_isolation_policy ON tenant_idp_certificates
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- tenant_identity_providers table (015_create_oidc_federation.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_identity_providers_tenant_isolation ON tenant_identity_providers;
CREATE POLICY tenant_identity_providers_tenant_isolation ON tenant_identity_providers
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS identity_provider_domains_tenant_isolation ON identity_provider_domains;
CREATE POLICY identity_provider_domains_tenant_isolation ON identity_provider_domains
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS user_identity_links_tenant_isolation ON user_identity_links;
CREATE POLICY user_identity_links_tenant_isolation ON user_identity_links
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS federated_auth_sessions_tenant_isolation ON federated_auth_sessions;
CREATE POLICY federated_auth_sessions_tenant_isolation ON federated_auth_sessions
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- scim_* tables (016_create_scim_tables.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_tokens;
CREATE POLICY tenant_isolation_policy ON scim_tokens
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON scim_attribute_mappings;
CREATE POLICY tenant_isolation_policy ON scim_attribute_mappings
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON scim_audit_logs;
CREATE POLICY tenant_isolation_policy ON scim_audit_logs
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON groups;
CREATE POLICY tenant_isolation_policy ON groups
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON group_memberships;
CREATE POLICY tenant_isolation_policy ON group_memberships
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- mfa_* tables (018_create_mfa_tables.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON user_totp_secrets;
CREATE POLICY tenant_isolation_policy ON user_totp_secrets
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON user_recovery_codes;
CREATE POLICY tenant_isolation_policy ON user_recovery_codes
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON mfa_audit_log;
CREATE POLICY tenant_isolation_policy ON mfa_audit_log
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- session_* tables (019_create_session_tables.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON sessions;
CREATE POLICY tenant_isolation_policy ON sessions
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_session_policies;
CREATE POLICY tenant_isolation_policy ON tenant_session_policies
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- password_policies tables (020_password_policies_lockout.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_password_policies;
CREATE POLICY tenant_isolation_policy ON tenant_password_policies
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_lockout_policies;
CREATE POLICY tenant_isolation_policy ON tenant_lockout_policies
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON password_history;
CREATE POLICY tenant_isolation_policy ON password_history
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON failed_login_attempts;
CREATE POLICY tenant_isolation_policy ON failed_login_attempts
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- login_history and audit tables (021_login_history_audit.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON login_attempts;
CREATE POLICY tenant_isolation_policy ON login_attempts
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON security_alerts;
CREATE POLICY tenant_isolation_policy ON security_alerts
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON user_devices;
CREATE POLICY tenant_isolation_policy ON user_devices
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON user_locations;
CREATE POLICY tenant_isolation_policy ON user_locations
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- self_service profile (023_self_service_profile.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON email_change_requests;
CREATE POLICY tenant_isolation_policy ON email_change_requests
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- ip_* tables (024_ip_restrictions.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_ip_settings;
CREATE POLICY tenant_isolation_policy ON tenant_ip_settings
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON ip_restriction_rules;
CREATE POLICY tenant_isolation_policy ON ip_restriction_rules
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- delegated_admin_* tables (025_delegated_admin.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON admin_permissions;
CREATE POLICY tenant_isolation_policy ON admin_permissions
    FOR ALL
    USING (true); -- admin_permissions are global

DROP POLICY IF EXISTS tenant_isolation_policy ON admin_role_templates;
CREATE POLICY tenant_isolation_policy ON admin_role_templates
    FOR ALL
    USING (
        is_system = true
        OR tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

DROP POLICY IF EXISTS tenant_isolation_policy ON admin_role_template_permissions;
CREATE POLICY tenant_isolation_policy ON admin_role_template_permissions
    FOR ALL
    USING (true); -- junction table, protected by role template policy

DROP POLICY IF EXISTS tenant_isolation_policy ON user_admin_assignments;
CREATE POLICY tenant_isolation_policy ON user_admin_assignments
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON admin_audit_log;
CREATE POLICY tenant_isolation_policy ON admin_audit_log
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- branding_* tables (026_custom_branding.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_branding;
CREATE POLICY tenant_isolation_policy ON tenant_branding
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON branding_assets;
CREATE POLICY tenant_isolation_policy ON branding_assets
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation_policy ON email_templates;
CREATE POLICY tenant_isolation_policy ON email_templates
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- tenant_policies table (027_tenant_policies.sql)
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_policies;
CREATE POLICY tenant_isolation_policy ON tenant_policies
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- ============================================================================
-- webauthn_* tables (028_create_webauthn_tables.sql)
-- Note: These tables already have RLS policies with correct NULLIF pattern
-- from migration 028, so we just need to ensure consistency
-- ============================================================================
-- user_webauthn_credentials already has tenant_isolation_webauthn_creds policy
-- webauthn_challenges already has tenant_isolation_webauthn_challenges policy
-- tenant_webauthn_policies already has tenant_isolation_webauthn_policies policy
-- webauthn_audit_log already has tenant_isolation_webauthn_audit policy

COMMENT ON EXTENSION plpgsql IS 'Migration 029: Fixed all RLS policies to handle empty tenant context using NULLIF';
