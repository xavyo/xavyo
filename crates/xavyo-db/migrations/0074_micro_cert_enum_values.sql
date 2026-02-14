-- F055 Improvements Part 2: Add new enum values
-- These must be in a separate migration because ALTER TYPE ADD VALUE
-- cannot be rolled back and the values cannot be used in the same transaction.

-- Add 'reduce' and 'delegate' to micro_cert_decision enum
ALTER TYPE micro_cert_decision ADD VALUE IF NOT EXISTS 'reduce';
ALTER TYPE micro_cert_decision ADD VALUE IF NOT EXISTS 'delegate';

-- Add 'auto_revoked' (distinct from manual revoke) and 'flagged_for_review' (for Reduce)
ALTER TYPE micro_cert_status ADD VALUE IF NOT EXISTS 'auto_revoked';
ALTER TYPE micro_cert_status ADD VALUE IF NOT EXISTS 'flagged_for_review';

-- Add 'flagged_for_review' and 'delegated' event types
ALTER TYPE micro_cert_event_type ADD VALUE IF NOT EXISTS 'flagged_for_review';
ALTER TYPE micro_cert_event_type ADD VALUE IF NOT EXISTS 'delegated';
