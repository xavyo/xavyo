-- Add post-logout redirect URIs to OAuth clients for OIDC RP-Initiated Logout
ALTER TABLE oauth_clients
  ADD COLUMN IF NOT EXISTS post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}';
