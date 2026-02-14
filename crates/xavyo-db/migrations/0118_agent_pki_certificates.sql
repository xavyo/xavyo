-- Migration: Create agent PKI tables (F127)
-- Feature: Agent PKI & Certificate Issuance
-- Date: 2026-02-02

-- Certificate Authorities
-- Stores internal and external CA configurations for certificate signing
CREATE TABLE certificate_authorities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    ca_type VARCHAR(20) NOT NULL CHECK (ca_type IN ('internal', 'step_ca', 'vault_pki')),
    certificate_pem TEXT NOT NULL,
    chain_pem TEXT,
    private_key_encrypted BYTEA,
    private_key_ref VARCHAR(255),
    external_config JSONB,
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_default BOOLEAN NOT NULL DEFAULT false,
    max_validity_days INTEGER NOT NULL DEFAULT 365,
    subject_dn VARCHAR(512) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    crl_url VARCHAR(512),
    ocsp_url VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT check_internal_has_key CHECK (
        ca_type != 'internal' OR (private_key_encrypted IS NOT NULL OR private_key_ref IS NOT NULL)
    )
);

-- Index for tenant lookup
CREATE INDEX idx_certificate_authorities_tenant ON certificate_authorities(tenant_id);

-- Unique constraint: only one default CA per tenant
CREATE UNIQUE INDEX idx_certificate_authorities_default ON certificate_authorities(tenant_id)
    WHERE is_default = true;

-- Unique constraint: CA name must be unique per tenant
CREATE UNIQUE INDEX idx_certificate_authorities_name ON certificate_authorities(tenant_id, name);

-- Agent Certificates
-- Stores X.509 certificates issued to AI agents
CREATE TABLE agent_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    serial_number VARCHAR(64) NOT NULL,
    certificate_pem TEXT NOT NULL,
    fingerprint_sha256 VARCHAR(64) NOT NULL,
    subject_dn VARCHAR(512) NOT NULL,
    issuer_dn VARCHAR(512) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    ca_id UUID NOT NULL REFERENCES certificate_authorities(id) ON DELETE RESTRICT,
    revoked_at TIMESTAMPTZ,
    revocation_reason SMALLINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- Serial number must be unique globally (across all tenants)
CREATE UNIQUE INDEX idx_agent_certificates_serial ON agent_certificates(serial_number);

-- Index for agent certificate lookup
CREATE INDEX idx_agent_certificates_tenant_agent ON agent_certificates(tenant_id, agent_id);

-- Index for status-based queries
CREATE INDEX idx_agent_certificates_status ON agent_certificates(tenant_id, status);

-- Index for expiry-based queries (certificate renewal)
CREATE INDEX idx_agent_certificates_expiry ON agent_certificates(not_after);

-- Index for fingerprint lookup (mTLS validation)
CREATE INDEX idx_agent_certificates_fingerprint ON agent_certificates(fingerprint_sha256);

-- Certificate Revocations (audit log)
-- Stores revocation events for audit purposes
CREATE TABLE certificate_revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    certificate_id UUID NOT NULL REFERENCES agent_certificates(id) ON DELETE CASCADE,
    serial_number VARCHAR(64) NOT NULL,
    reason_code SMALLINT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    revoked_by UUID NOT NULL REFERENCES users(id),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for tenant lookup
CREATE INDEX idx_certificate_revocations_tenant ON certificate_revocations(tenant_id);

-- Index for serial number lookup (OCSP/CRL)
CREATE INDEX idx_certificate_revocations_serial ON certificate_revocations(serial_number);

-- Index for revocation time (CRL generation)
CREATE INDEX idx_certificate_revocations_time ON certificate_revocations(revoked_at);

-- Row-Level Security
ALTER TABLE certificate_authorities ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_revocations ENABLE ROW LEVEL SECURITY;

-- RLS Policies for certificate_authorities
CREATE POLICY tenant_isolation_certificate_authorities ON certificate_authorities
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- RLS Policies for agent_certificates
CREATE POLICY tenant_isolation_agent_certificates ON agent_certificates
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- RLS Policies for certificate_revocations
CREATE POLICY tenant_isolation_certificate_revocations ON certificate_revocations
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- Comments for documentation
COMMENT ON TABLE certificate_authorities IS 'Certificate Authority configurations for AI agent PKI (F127)';
COMMENT ON TABLE agent_certificates IS 'X.509 certificates issued to AI agents for mTLS authentication (F127)';
COMMENT ON TABLE certificate_revocations IS 'Certificate revocation audit log for CRL/OCSP (F127)';

COMMENT ON COLUMN certificate_authorities.ca_type IS 'Type: internal (rcgen), step_ca, vault_pki';
COMMENT ON COLUMN certificate_authorities.private_key_encrypted IS 'AES-256-GCM encrypted private key (internal CA only)';
COMMENT ON COLUMN certificate_authorities.private_key_ref IS 'Reference to private key in xavyo-secrets';
COMMENT ON COLUMN certificate_authorities.external_config IS 'Provider-specific configuration (step-ca URL, Vault mount, etc.)';
COMMENT ON COLUMN certificate_authorities.is_default IS 'Default CA for tenant (unique constraint ensures only one)';
COMMENT ON COLUMN certificate_authorities.max_validity_days IS 'Maximum certificate validity period in days';

COMMENT ON COLUMN agent_certificates.serial_number IS 'Certificate serial number (hex-encoded, globally unique)';
COMMENT ON COLUMN agent_certificates.fingerprint_sha256 IS 'SHA-256 fingerprint for quick lookup during mTLS validation';
COMMENT ON COLUMN agent_certificates.status IS 'active, revoked, or expired';
COMMENT ON COLUMN agent_certificates.revocation_reason IS 'RFC 5280 revocation reason code (0-10)';

COMMENT ON COLUMN certificate_revocations.reason_code IS 'RFC 5280 revocation reason: 0=unspecified, 1=keyCompromise, 4=superseded, 5=cessationOfOperation';
