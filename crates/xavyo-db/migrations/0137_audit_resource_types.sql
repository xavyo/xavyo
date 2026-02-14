-- Add missing resource types to admin_audit_log constraint
-- Required for tenant provisioning audit trail (F-AUDIT-PROV)

ALTER TABLE admin_audit_log DROP CONSTRAINT IF EXISTS chk_audit_resource_type;

ALTER TABLE admin_audit_log ADD CONSTRAINT chk_audit_resource_type 
  CHECK (resource_type IN (
    'user', 
    'template', 
    'assignment', 
    'permission', 
    'tenant', 
    'api_key', 
    'oauth_client',
    'mfa_policy',
    'session_policy',
    'password_policy'
  ));

COMMENT ON CONSTRAINT chk_audit_resource_type ON admin_audit_log IS 
  'Valid resource types for admin audit logging. Extended for tenant provisioning.';
