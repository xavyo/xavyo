-- Add SLO URL to service providers
ALTER TABLE saml_service_providers
  ADD COLUMN IF NOT EXISTS slo_url TEXT,
  ADD COLUMN IF NOT EXISTS slo_binding TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

-- Track which SPs have active sessions per user (for SLO dispatch)
CREATE TABLE IF NOT EXISTS saml_sp_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sp_id UUID NOT NULL REFERENCES saml_service_providers(id) ON DELETE CASCADE,
  session_index TEXT NOT NULL,
  name_id TEXT NOT NULL,
  name_id_format TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  CONSTRAINT uq_saml_sp_session UNIQUE (tenant_id, user_id, sp_id, session_index)
);

CREATE INDEX IF NOT EXISTS idx_saml_sp_sessions_user ON saml_sp_sessions(tenant_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_saml_sp_sessions_expires ON saml_sp_sessions(expires_at) WHERE revoked_at IS NULL;

-- RLS
ALTER TABLE saml_sp_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_sp_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_saml_sp_sessions ON saml_sp_sessions;
CREATE POLICY tenant_isolation_saml_sp_sessions ON saml_sp_sessions
  FOR ALL
  USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
