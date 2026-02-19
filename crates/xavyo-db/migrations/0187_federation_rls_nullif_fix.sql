-- Migration: Fix RLS NULLIF pattern on federation tables
-- These 8 tables were missed by migration 0146 which fixed 150+ other tables.
-- The old pattern errors on empty string instead of returning no rows.

-- 1. tenant_identity_providers
DROP POLICY IF EXISTS tenant_isolation ON tenant_identity_providers;
CREATE POLICY tenant_isolation ON tenant_identity_providers
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 2. identity_provider_domains
DROP POLICY IF EXISTS tenant_isolation ON identity_provider_domains;
CREATE POLICY tenant_isolation ON identity_provider_domains
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 3. user_identity_links
DROP POLICY IF EXISTS tenant_isolation ON user_identity_links;
CREATE POLICY tenant_isolation ON user_identity_links
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 4. saml_service_providers
DROP POLICY IF EXISTS tenant_isolation ON saml_service_providers;
CREATE POLICY tenant_isolation ON saml_service_providers
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 5. tenant_idp_certificates
DROP POLICY IF EXISTS tenant_isolation ON tenant_idp_certificates;
CREATE POLICY tenant_isolation ON tenant_idp_certificates
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 6. oauth_clients
DROP POLICY IF EXISTS tenant_isolation ON oauth_clients;
CREATE POLICY tenant_isolation ON oauth_clients
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 7. social_connections
DROP POLICY IF EXISTS tenant_isolation ON social_connections;
CREATE POLICY tenant_isolation ON social_connections
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 8. tenant_social_providers
DROP POLICY IF EXISTS tenant_isolation ON tenant_social_providers;
CREATE POLICY tenant_isolation ON tenant_social_providers
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
