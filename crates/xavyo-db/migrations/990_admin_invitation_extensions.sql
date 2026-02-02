-- Migration: Extend user_invitations for admin invite flow
-- Feature: F-ADMIN-INVITE - Admin User Invitation Flow
-- Description: Add fields for admin-specific invitations

-- Add invited_by_user_id (who created the invitation)
ALTER TABLE user_invitations
ADD COLUMN IF NOT EXISTS invited_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Add role_template_id (optional role assignment)
ALTER TABLE user_invitations
ADD COLUMN IF NOT EXISTS role_template_id UUID REFERENCES admin_role_templates(id) ON DELETE SET NULL;

-- Add email field (for inviting users that don't exist yet)
-- Note: user_id can be NULL for admin invites where user is created on acceptance
ALTER TABLE user_invitations
ADD COLUMN IF NOT EXISTS email VARCHAR(255);

-- Make user_id nullable (for admin invites where user doesn't exist yet)
ALTER TABLE user_invitations
ALTER COLUMN user_id DROP NOT NULL;

-- Update status constraint to include 'cancelled'
ALTER TABLE user_invitations
DROP CONSTRAINT IF EXISTS user_invitations_status_check;

ALTER TABLE user_invitations
ADD CONSTRAINT user_invitations_status_check CHECK (
    status IN ('pending', 'sent', 'accepted', 'expired', 'cancelled')
);

-- Index for listing invitations by inviter
CREATE INDEX IF NOT EXISTS idx_user_invitations_invited_by
    ON user_invitations(tenant_id, invited_by_user_id)
    WHERE invited_by_user_id IS NOT NULL;

-- Index for email duplicate check (pending invitations)
CREATE INDEX IF NOT EXISTS idx_user_invitations_email_pending
    ON user_invitations(tenant_id, email)
    WHERE status IN ('pending', 'sent') AND email IS NOT NULL;

-- Comment updates
COMMENT ON COLUMN user_invitations.invited_by_user_id IS 'Admin user who created this invitation (NULL for bulk import)';
COMMENT ON COLUMN user_invitations.role_template_id IS 'Role template to assign on acceptance (NULL for default role)';
COMMENT ON COLUMN user_invitations.email IS 'Invitee email address (for admin invites where user does not exist yet)';
