-- GDPR/Data Protection Metadata (F-067)
-- Adds data protection classification and related fields to gov_entitlements

-- Create enum types
DO $$ BEGIN
    CREATE TYPE data_protection_classification AS ENUM (
        'none',
        'personal',
        'sensitive',
        'special_category'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE gdpr_legal_basis AS ENUM (
        'consent',
        'contract',
        'legal_obligation',
        'vital_interest',
        'public_task',
        'legitimate_interest'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Add GDPR columns to gov_entitlements
ALTER TABLE gov_entitlements
    ADD COLUMN IF NOT EXISTS data_protection_classification data_protection_classification NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS legal_basis gdpr_legal_basis,
    ADD COLUMN IF NOT EXISTS retention_period_days INTEGER,
    ADD COLUMN IF NOT EXISTS data_controller VARCHAR(500),
    ADD COLUMN IF NOT EXISTS data_processor VARCHAR(500),
    ADD COLUMN IF NOT EXISTS purposes TEXT[];

-- Indexes for GDPR filtering and reporting
CREATE INDEX IF NOT EXISTS idx_gov_entitlements_classification
    ON gov_entitlements(tenant_id, data_protection_classification);

CREATE INDEX IF NOT EXISTS idx_gov_entitlements_legal_basis
    ON gov_entitlements(tenant_id, legal_basis)
    WHERE legal_basis IS NOT NULL;
