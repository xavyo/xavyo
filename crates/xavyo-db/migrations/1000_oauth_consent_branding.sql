-- Add per-client branding fields to oauth_clients
ALTER TABLE oauth_clients
  ADD COLUMN logo_url TEXT,
  ADD COLUMN description TEXT;

-- Add consent page customization fields to tenant_branding
ALTER TABLE tenant_branding
  ADD COLUMN consent_page_title VARCHAR(255),
  ADD COLUMN consent_page_subtitle VARCHAR(500),
  ADD COLUMN consent_approval_button_text VARCHAR(100),
  ADD COLUMN consent_denial_button_text VARCHAR(100);
