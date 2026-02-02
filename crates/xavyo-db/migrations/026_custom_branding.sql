-- Migration: 026_custom_branding
-- Feature: F030 - Custom Branding
-- Description: Create tables for tenant branding, assets, and email templates

-- ============================================================================
-- Table: tenant_branding
-- Purpose: Visual customization settings for a tenant's login pages and UI
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_branding (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    logo_url VARCHAR(500),
    logo_dark_url VARCHAR(500),
    favicon_url VARCHAR(500),
    email_logo_url VARCHAR(500),
    primary_color VARCHAR(7) CHECK (primary_color IS NULL OR primary_color ~ '^#[0-9A-Fa-f]{6}$'),
    secondary_color VARCHAR(7) CHECK (secondary_color IS NULL OR secondary_color ~ '^#[0-9A-Fa-f]{6}$'),
    accent_color VARCHAR(7) CHECK (accent_color IS NULL OR accent_color ~ '^#[0-9A-Fa-f]{6}$'),
    background_color VARCHAR(7) CHECK (background_color IS NULL OR background_color ~ '^#[0-9A-Fa-f]{6}$'),
    text_color VARCHAR(7) CHECK (text_color IS NULL OR text_color ~ '^#[0-9A-Fa-f]{6}$'),
    font_family VARCHAR(100),
    custom_css TEXT,
    login_page_title VARCHAR(200),
    login_page_subtitle VARCHAR(500),
    login_page_background_url VARCHAR(500),
    footer_text VARCHAR(500),
    privacy_policy_url VARCHAR(500),
    terms_of_service_url VARCHAR(500),
    support_url VARCHAR(500),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for tenant lookup (primary key already indexed)
COMMENT ON TABLE tenant_branding IS 'Visual customization settings for tenant login pages and UI';

-- ============================================================================
-- Table: branding_assets
-- Purpose: Metadata for uploaded image files (actual files stored on filesystem/S3)
-- ============================================================================

CREATE TABLE IF NOT EXISTS branding_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_type VARCHAR(20) NOT NULL CHECK (asset_type IN ('logo', 'favicon', 'background', 'email_logo')),
    filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(50) NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml')),
    file_size INTEGER NOT NULL CHECK (file_size > 0 AND file_size <= 2097152), -- Max 2MB
    storage_path VARCHAR(500) NOT NULL,
    width INTEGER NOT NULL CHECK (width > 0 AND width <= 4096),
    height INTEGER NOT NULL CHECK (height > 0 AND height <= 4096),
    checksum VARCHAR(64) NOT NULL, -- SHA-256 hash
    uploaded_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for common queries
CREATE INDEX idx_branding_assets_tenant ON branding_assets(tenant_id, created_at DESC);
CREATE INDEX idx_branding_assets_type ON branding_assets(tenant_id, asset_type);
CREATE INDEX idx_branding_assets_checksum ON branding_assets(tenant_id, checksum);

COMMENT ON TABLE branding_assets IS 'Metadata for uploaded branding image files';

-- ============================================================================
-- Table: email_templates
-- Purpose: Custom email templates for various system emails
-- ============================================================================

CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    template_type VARCHAR(30) NOT NULL CHECK (template_type IN (
        'welcome',
        'password_reset',
        'email_verification',
        'mfa_setup',
        'security_alert',
        'account_locked'
    )),
    locale VARCHAR(10) NOT NULL DEFAULT 'en',
    subject VARCHAR(200) NOT NULL,
    body_html TEXT NOT NULL,
    body_text TEXT,
    available_variables JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Unique constraint: one template per tenant + type + locale
    CONSTRAINT unique_template_per_tenant_type_locale UNIQUE (tenant_id, template_type, locale)
);

-- Indexes for common queries
CREATE INDEX idx_email_templates_tenant_type ON email_templates(tenant_id, template_type, locale);
CREATE INDEX idx_email_templates_active ON email_templates(tenant_id, is_active) WHERE is_active = true;

COMMENT ON TABLE email_templates IS 'Custom email templates for tenant communications';

-- ============================================================================
-- Row Level Security
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE branding_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;

-- tenant_branding policies
CREATE POLICY tenant_isolation_branding_select ON tenant_branding
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_branding_insert ON tenant_branding
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_branding_update ON tenant_branding
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_branding_delete ON tenant_branding
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- branding_assets policies
CREATE POLICY tenant_isolation_assets_select ON branding_assets
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_assets_insert ON branding_assets
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_assets_update ON branding_assets
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_assets_delete ON branding_assets
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- email_templates policies
CREATE POLICY tenant_isolation_templates_select ON email_templates
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_templates_insert ON email_templates
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_templates_update ON email_templates
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY tenant_isolation_templates_delete ON email_templates
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Triggers for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_tenant_branding_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_tenant_branding_updated_at
    BEFORE UPDATE ON tenant_branding
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_branding_updated_at();

CREATE OR REPLACE FUNCTION update_email_templates_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_email_templates_updated_at
    BEFORE UPDATE ON email_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_email_templates_updated_at();
