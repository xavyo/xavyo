-- Migration: Add missing foreign key constraints on NHI tables
--
-- Several UUID columns in the NHI lifecycle tables (migration 061_001) reference
-- users but lack FK constraints, allowing orphaned references if users are deleted.

-- gov_service_accounts.backup_owner_id -> users(id)
DO $$ BEGIN
    ALTER TABLE gov_service_accounts
        ADD CONSTRAINT fk_service_accounts_backup_owner
        FOREIGN KEY (backup_owner_id) REFERENCES users(id) ON DELETE SET NULL;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- gov_nhi_credentials.rotated_by -> users(id)
DO $$ BEGIN
    ALTER TABLE gov_nhi_credentials
        ADD CONSTRAINT fk_nhi_credentials_rotated_by
        FOREIGN KEY (rotated_by) REFERENCES users(id) ON DELETE SET NULL;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- gov_nhi_requests.requester_id -> users(id)
DO $$ BEGIN
    ALTER TABLE gov_nhi_requests
        ADD CONSTRAINT fk_nhi_requests_requester
        FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE RESTRICT;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- gov_nhi_requests.approver_id -> users(id)
DO $$ BEGIN
    ALTER TABLE gov_nhi_requests
        ADD CONSTRAINT fk_nhi_requests_approver
        FOREIGN KEY (approver_id) REFERENCES users(id) ON DELETE SET NULL;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- gov_nhi_audit_events.actor_id -> users(id)
DO $$ BEGIN
    ALTER TABLE gov_nhi_audit_events
        ADD CONSTRAINT fk_nhi_audit_events_actor
        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;
