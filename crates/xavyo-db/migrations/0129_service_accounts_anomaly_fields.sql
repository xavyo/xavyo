-- Migration: F108 - Add anomaly detection fields to service accounts
-- Purpose: Cross-pollinate behavioral anomaly detection from AI agents to service accounts

-- Add anomaly detection configuration
ALTER TABLE gov_service_accounts ADD COLUMN IF NOT EXISTS anomaly_threshold DECIMAL(5,2) DEFAULT 2.5;
ALTER TABLE gov_service_accounts ADD COLUMN IF NOT EXISTS last_anomaly_check_at TIMESTAMPTZ;
ALTER TABLE gov_service_accounts ADD COLUMN IF NOT EXISTS anomaly_baseline JSONB;

-- Index for anomaly check scheduling
CREATE INDEX IF NOT EXISTS idx_gov_service_accounts_anomaly_check
ON gov_service_accounts(tenant_id, last_anomaly_check_at)
WHERE anomaly_threshold IS NOT NULL;

-- Comments for documentation
COMMENT ON COLUMN gov_service_accounts.anomaly_threshold IS 'F108: Z-score threshold for anomaly detection (default 2.5 = ~99% confidence)';
COMMENT ON COLUMN gov_service_accounts.last_anomaly_check_at IS 'F108: Timestamp of last anomaly detection run';
COMMENT ON COLUMN gov_service_accounts.anomaly_baseline IS 'F108: JSON baseline metrics for behavioral comparison';
