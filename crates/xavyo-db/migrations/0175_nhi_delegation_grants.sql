-- NHI Delegation Grants: allows one NHI to act on behalf of a user or another NHI.
-- Implements RFC 8693 Token Exchange delegation model.

CREATE TABLE nhi_delegation_grants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  -- Who is being represented (the principal)
  principal_id UUID NOT NULL,
  principal_type VARCHAR(20) NOT NULL CHECK (principal_type IN ('user', 'nhi')),
  -- Who is doing the acting (always an NHI)
  actor_nhi_id UUID NOT NULL REFERENCES nhi_identities(id) ON DELETE CASCADE,
  -- Scope constraints
  allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
  allowed_resource_types TEXT[] NOT NULL DEFAULT '{}',
  max_delegation_depth INT NOT NULL DEFAULT 1 CHECK (max_delegation_depth BETWEEN 1 AND 5),
  -- Lifecycle
  status VARCHAR(20) NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'expired', 'revoked')),
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  granted_by UUID,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revoked_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, principal_id, actor_nhi_id)
);

-- Index for looking up grants by actor (token exchange path)
CREATE INDEX idx_nhi_delegation_grants_actor ON nhi_delegation_grants(tenant_id, actor_nhi_id);
-- Index for looking up grants by principal (management/listing path)
CREATE INDEX idx_nhi_delegation_grants_principal ON nhi_delegation_grants(tenant_id, principal_id);

-- Enable Row Level Security
ALTER TABLE nhi_delegation_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY nhi_delegation_grants_tenant_isolation ON nhi_delegation_grants
  USING (tenant_id::text = current_setting('app.current_tenant', true));
