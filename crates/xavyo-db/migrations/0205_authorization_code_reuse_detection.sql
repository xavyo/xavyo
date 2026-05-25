-- Migration: Authorization code reuse detection (RFC 6749 §10.5)
--
-- Previously, the OAuth authorization-code redemption path DELETEd the row
-- on success, making the `used = TRUE` reuse-detection branch in
-- `validate_and_consume_code` unreachable. We keep the row (with
-- `used = TRUE` + `consumed_at`) so a second redemption attempt can be
-- *detected* (not just denied), letting the server revoke the
-- previously-issued token family via the existing `revoke-all` sentinel.
--
-- The expired-row cleanup runs against `expires_at` (already indexed) and
-- now also against `consumed_at + 1 day` so consumed-and-expired rows are
-- vacuumable.

ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;

ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS consumed_by_jti TEXT;

CREATE INDEX IF NOT EXISTS idx_authorization_codes_consumed_at
    ON authorization_codes(consumed_at)
    WHERE consumed_at IS NOT NULL;

COMMENT ON COLUMN authorization_codes.consumed_at
    IS 'Timestamp when the code was redeemed for tokens (NULL if not yet consumed)';
COMMENT ON COLUMN authorization_codes.consumed_by_jti
    IS 'JTI of the access token issued from this code; lets the server revoke the issued family on detected reuse';
