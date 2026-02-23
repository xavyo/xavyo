-- Migration: Widen SAML session request_id column
-- Salesforce uses AuthnRequest IDs up to ~300 characters.
-- The parser already allows up to 1024; align the DB column.

ALTER TABLE saml_authn_request_sessions
    ALTER COLUMN request_id TYPE VARCHAR(1024);
