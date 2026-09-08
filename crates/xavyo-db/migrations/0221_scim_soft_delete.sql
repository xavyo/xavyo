-- SCIM must distinguish a *deactivated* user (active=false, still exists and can be
-- read/reactivated/deleted) from a *deleted* user (gone; GET must 404 per RFC 7644
-- Section 3.6). Previously the SCIM layer overloaded `is_active` for both, so once an
-- IdP (Okta/Azure) deactivated a user via PATCH active=false the user became invisible:
-- it could no longer be fetched, reactivated, or deleted through SCIM. This dedicated
-- soft-delete marker lets deactivation and deletion be independent.
ALTER TABLE users ADD COLUMN IF NOT EXISTS scim_deleted_at TIMESTAMPTZ;

-- Fast lookups that exclude SCIM-deleted rows (the common SCIM read/list path).
CREATE INDEX IF NOT EXISTS idx_users_scim_deleted_at
    ON users (tenant_id)
    WHERE scim_deleted_at IS NULL;
