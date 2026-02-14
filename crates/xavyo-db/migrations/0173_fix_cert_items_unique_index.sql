-- Fix #6: Allow cross-campaign coverage for same user+entitlement
-- Previous index was global (tenant_id, user_id, entitlement_id) which blocked
-- overlapping campaigns from reviewing the same user+entitlement pair.
-- New index includes campaign_id for per-campaign uniqueness.
DROP INDEX IF EXISTS idx_cert_items_unique_pending;
CREATE UNIQUE INDEX idx_cert_items_unique_pending
    ON gov_certification_items(tenant_id, campaign_id, user_id, entitlement_id)
    WHERE status = 'pending';
