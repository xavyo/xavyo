-- Remove unused 'delegate' permission type from nhi_nhi_permissions.
-- Delegation is now handled by the dedicated nhi_delegation_grants table.
DELETE FROM nhi_nhi_permissions WHERE permission_type = 'delegate';
ALTER TABLE nhi_nhi_permissions DROP CONSTRAINT IF EXISTS nhi_nhi_permissions_permission_type_check;
ALTER TABLE nhi_nhi_permissions ADD CONSTRAINT nhi_nhi_permissions_permission_type_check
  CHECK (permission_type IN ('call'));
