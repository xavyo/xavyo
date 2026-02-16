-- Add 'nhi' target type to gov_assignment_target_type enum.
-- This allows entitlement assignments directly to NHI identities (agents,
-- service accounts, tools) instead of requiring the target_type='user' hack.
--
-- NOTE: ALTER TYPE ADD VALUE cannot be used in the same transaction as a
-- statement that references the new value. The index using 'nhi' is created
-- in migration 0181.

ALTER TYPE gov_assignment_target_type ADD VALUE IF NOT EXISTS 'nhi';
