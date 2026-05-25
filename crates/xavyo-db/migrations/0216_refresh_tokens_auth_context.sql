-- Migration: carry the OIDC authentication context across refresh.
--
-- A refreshed access token must keep the ORIGINAL acr/amr/auth_time (OIDC: the
-- time/strength of the end-user authentication, not of token issuance) so that
-- RFC 9470 step-up checks and `max_age` stay meaningful after token rotation —
-- otherwise a user who completed MFA (acr "2") would be re-challenged on the
-- first refresh. Capture them on the refresh-token row at login; the refresh
-- re-issue path reads them back and stamps the new access token.
--
-- All nullable: refresh tokens issued before this change (or non-interactive
-- issuance) simply carry no context.

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS acr TEXT,
    ADD COLUMN IF NOT EXISTS amr TEXT[],
    ADD COLUMN IF NOT EXISTS auth_time BIGINT;

COMMENT ON COLUMN refresh_tokens.acr IS 'OIDC acr captured at login, carried forward to refreshed access tokens';
COMMENT ON COLUMN refresh_tokens.amr IS 'OIDC amr (RFC 8176) captured at login, carried forward on refresh';
COMMENT ON COLUMN refresh_tokens.auth_time IS 'OIDC auth_time (Unix seconds) captured at login, carried forward on refresh';
