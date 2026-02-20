-- A5: Add functional index on LOWER(email) for case-insensitive email lookups.
--
-- The users API filters with `LOWER(email) LIKE ...` which cannot use the
-- existing B-tree index on (tenant_id, email). This composite functional index
-- covers both exact and LIKE prefix searches on normalised email addresses.

CREATE INDEX IF NOT EXISTS idx_users_tenant_email_lower
    ON users (tenant_id, LOWER(email));
