-- Migration: 007_add_user_email_verified
-- Feature: F007 - Password Reset & Email Verification
-- Description: Add email verification status columns to users table

-- Add email_verified column with default FALSE for new users
ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Add email_verified_at timestamp column
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMPTZ NULL;

-- Grandfather clause: Mark existing users as verified to avoid breaking their sessions
-- This ensures backwards compatibility with F006 registrations
UPDATE users SET email_verified = TRUE, email_verified_at = created_at WHERE email_verified = FALSE;

-- Index for querying unverified users (useful for admin dashboard)
CREATE INDEX idx_users_email_verified ON users(email_verified) WHERE email_verified = FALSE;

-- Comment on columns
COMMENT ON COLUMN users.email_verified IS 'Whether the user has verified their email address';
COMMENT ON COLUMN users.email_verified_at IS 'Timestamp when email was verified - NULL if not verified';
