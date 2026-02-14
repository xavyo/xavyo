-- Migration: 030_add_display_name_to_users.sql
-- Purpose: Add display_name column to users table
-- This column is expected by the User model but was missing from the schema

ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);

-- Add index for display name searches
CREATE INDEX IF NOT EXISTS idx_users_display_name ON users(display_name) WHERE display_name IS NOT NULL;

COMMENT ON COLUMN users.display_name IS 'User''s display name (optional, used for UI display)';
