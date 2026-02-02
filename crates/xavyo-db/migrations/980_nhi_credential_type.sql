-- F110: Add nhi_type column to gov_nhi_credentials
-- This allows credentials to be associated with either service accounts or AI agents

-- Add nhi_type column to distinguish credential owner type
ALTER TABLE gov_nhi_credentials
ADD COLUMN IF NOT EXISTS nhi_type VARCHAR(20) NOT NULL DEFAULT 'service_account'
CHECK (nhi_type IN ('service_account', 'agent'));

-- Index for faster lookups during authentication
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_nhi_type_active
ON gov_nhi_credentials(nhi_type) WHERE is_active = true;

-- Composite index for auth lookup (credential is active + valid time window)
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_auth_lookup
ON gov_nhi_credentials(is_active, valid_from, valid_until, nhi_type)
WHERE is_active = true;

COMMENT ON COLUMN gov_nhi_credentials.nhi_type IS 'Type of NHI: service_account or agent';
