-- Add role column to user_invitations for preserving the invited role
-- across creation and acceptance. PostgreSQL 11+ backfills existing rows.
ALTER TABLE user_invitations ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member';
