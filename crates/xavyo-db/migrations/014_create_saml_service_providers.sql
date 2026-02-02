-- Migration: 014_create_saml_service_providers.sql
-- SAML 2.0 Identity Provider tables

-- SAML Service Providers table
CREATE TABLE saml_service_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id VARCHAR(512) NOT NULL,
    name VARCHAR(255) NOT NULL,
    acs_urls TEXT[] NOT NULL,
    certificate TEXT,
    attribute_mapping JSONB DEFAULT '{}',
    name_id_format VARCHAR(128) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    sign_assertions BOOLEAN DEFAULT TRUE,
    validate_signatures BOOLEAN DEFAULT FALSE,
    assertion_validity_seconds INTEGER DEFAULT 300,
    enabled BOOLEAN DEFAULT TRUE,
    metadata_url VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_saml_sp_tenant_entity UNIQUE (tenant_id, entity_id),
    CONSTRAINT chk_assertion_validity CHECK (assertion_validity_seconds >= 60 AND assertion_validity_seconds <= 3600)
);

-- Index for enabled SPs per tenant
CREATE INDEX idx_saml_sp_tenant_enabled ON saml_service_providers(tenant_id) WHERE enabled = TRUE;

-- Enable RLS
ALTER TABLE saml_service_providers ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policy
CREATE POLICY tenant_isolation ON saml_service_providers
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Trigger for updated_at
CREATE TRIGGER set_updated_at_saml_sp
    BEFORE UPDATE ON saml_service_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


-- Tenant IdP Certificates table
CREATE TABLE tenant_idp_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    certificate TEXT NOT NULL,
    private_key_encrypted BYTEA NOT NULL,
    key_id VARCHAR(64) NOT NULL,
    subject_dn VARCHAR(512) NOT NULL,
    issuer_dn VARCHAR(512) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_idp_cert_tenant_key_id UNIQUE (tenant_id, key_id)
);

-- Index for active certificate per tenant
CREATE INDEX idx_idp_cert_tenant_active ON tenant_idp_certificates(tenant_id) WHERE is_active = TRUE;

-- Enable RLS
ALTER TABLE tenant_idp_certificates ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policy
CREATE POLICY tenant_isolation ON tenant_idp_certificates
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Function to ensure only one active certificate per tenant
CREATE OR REPLACE FUNCTION ensure_single_active_idp_cert()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_active = TRUE THEN
        UPDATE tenant_idp_certificates
        SET is_active = FALSE
        WHERE tenant_id = NEW.tenant_id
          AND id != NEW.id
          AND is_active = TRUE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ensure_single_active_cert
    BEFORE INSERT OR UPDATE ON tenant_idp_certificates
    FOR EACH ROW
    WHEN (NEW.is_active = TRUE)
    EXECUTE FUNCTION ensure_single_active_idp_cert();
