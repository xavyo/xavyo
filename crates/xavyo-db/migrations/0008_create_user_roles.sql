-- Migration: Create user_roles table for role assignments
-- Description: Stores role assignments for users with cascade delete

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, role_name)
);

-- Index for querying users by role
CREATE INDEX IF NOT EXISTS idx_user_roles_role_name ON user_roles(role_name);

COMMENT ON TABLE user_roles IS 'Role assignments for users';
COMMENT ON COLUMN user_roles.user_id IS 'Reference to the user';
COMMENT ON COLUMN user_roles.role_name IS 'Role identifier (e.g., admin, user)';
COMMENT ON COLUMN user_roles.created_at IS 'When the role was assigned';
