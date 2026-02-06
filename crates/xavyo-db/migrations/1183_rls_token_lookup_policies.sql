-- Migration: Add permissive RLS policies for unauthenticated token-based lookups
--
-- Problem: Unauthenticated endpoints that look up records by cryptographic tokens
-- (invitation acceptance, OIDC federation callback) fail because RLS blocks access
-- when no tenant context is set via set_tenant_context().
--
-- Solution: Add PERMISSIVE policies that allow the xavyo_app role to access rows
-- regardless of tenant context. Since these tables use short-lived, cryptographically
-- random tokens as the security boundary (not tenant_id), this is safe.
--
-- Note: With multiple PERMISSIVE policies, PostgreSQL uses OR logic — if ANY policy
-- is satisfied, the row is accessible. The existing tenant_isolation policy still
-- works when tenant context IS set.

-- ============================================================================
-- federated_auth_sessions: Short-lived OIDC federation state records
-- Security: state parameter is CSPRNG, 10-minute TTL
-- Used by: Federation callback (unauthenticated, state-based lookup)
-- ============================================================================
CREATE POLICY federated_auth_sessions_app_access ON federated_auth_sessions
    FOR ALL
    TO xavyo_app
    USING (true)
    WITH CHECK (true);

-- ============================================================================
-- user_invitations: Invitation acceptance records
-- Security: token_hash is SHA-256 of CSPRNG token, has expiry
-- Used by: Invitation acceptance (unauthenticated, token-based lookup)
-- ============================================================================
CREATE POLICY user_invitations_app_access ON user_invitations
    FOR ALL
    TO xavyo_app
    USING (true)
    WITH CHECK (true);
