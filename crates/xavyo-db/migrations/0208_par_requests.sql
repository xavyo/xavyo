-- Migration: Pushed Authorization Requests (RFC 9126)
--
-- Stores authorization request parameters pushed via POST /oauth/par. The
-- client receives an opaque, single-use `request_uri` (urn:ietf:params:oauth:
-- request_uri:<ref>) to present at GET /oauth/authorize. Short-lived (~90s),
-- single-use, tenant-isolated. Mirrors the authorization_codes shape.

CREATE TABLE IF NOT EXISTS par_requests (
    request_uri TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Public client_id string the request is bound to (must match at /authorize).
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    state TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    nonce TEXT,
    response_type TEXT NOT NULL DEFAULT 'code',
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT par_code_challenge_method_s256 CHECK (code_challenge_method = 'S256')
);

-- Cleanup index for vacuuming expired/used requests.
CREATE INDEX IF NOT EXISTS idx_par_requests_expires_at ON par_requests(expires_at);

-- Tenant-scoped RLS.
ALTER TABLE par_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE par_requests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON par_requests;
CREATE POLICY tenant_isolation_policy ON par_requests
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE par_requests IS 'Pushed Authorization Requests (RFC 9126): single-use, short-lived authorization request params referenced by request_uri';
