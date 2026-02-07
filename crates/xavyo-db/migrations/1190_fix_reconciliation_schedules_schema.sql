-- Migration 1190: Fix gov_reconciliation_schedules schema mismatch
--
-- The table was originally created by migration 040 with a different schema.
-- Migration 049 tried to recreate it with IF NOT EXISTS, which preserved the old schema.
-- The code (ReconciliationSchedule model) expects: connector_id, mode, enabled, last_run_id.
-- The actual table has: is_enabled, last_run_at, and is missing connector_id, mode, last_run_id.
--
-- This migration adds the missing columns and renames is_enabled -> enabled.

-- Step 1: Add missing columns
ALTER TABLE gov_reconciliation_schedules
    ADD COLUMN IF NOT EXISTS connector_id UUID,
    ADD COLUMN IF NOT EXISTS mode VARCHAR(20) NOT NULL DEFAULT 'full',
    ADD COLUMN IF NOT EXISTS last_run_id UUID;

-- Step 2: Rename is_enabled to enabled (if is_enabled exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'gov_reconciliation_schedules' AND column_name = 'is_enabled'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'gov_reconciliation_schedules' AND column_name = 'enabled'
    ) THEN
        ALTER TABLE gov_reconciliation_schedules RENAME COLUMN is_enabled TO enabled;
    END IF;
END $$;

-- Step 3: Drop the old unique constraint on tenant_id only (if exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'gov_reconciliation_schedules_tenant_id_key'
    ) THEN
        ALTER TABLE gov_reconciliation_schedules
            DROP CONSTRAINT gov_reconciliation_schedules_tenant_id_key;
    END IF;
END $$;

-- Step 4: Add unique constraint on (tenant_id, connector_id) if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_recon_schedule_tenant_connector'
    ) THEN
        ALTER TABLE gov_reconciliation_schedules
            ADD CONSTRAINT uq_recon_schedule_tenant_connector UNIQUE (tenant_id, connector_id);
    END IF;
END $$;

-- Step 5: Fix the index that referenced is_enabled
DROP INDEX IF EXISTS idx_recon_schedule_next;
CREATE INDEX IF NOT EXISTS idx_recon_schedule_next
    ON gov_reconciliation_schedules(next_run_at)
    WHERE enabled = true;

-- Step 6: Add frequency CHECK constraint to include 'hourly' if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_frequency'
          AND conrelid = 'gov_reconciliation_schedules'::regclass
    ) THEN
        ALTER TABLE gov_reconciliation_schedules DROP CONSTRAINT chk_frequency;
    END IF;
    ALTER TABLE gov_reconciliation_schedules
        ADD CONSTRAINT chk_frequency CHECK (
            frequency IN ('hourly', 'daily', 'weekly', 'monthly')
            OR frequency LIKE '% % % % %'
        );
END $$;

-- Step 7: Add FK for connector_id (optional, may not have connector_configurations)
-- Skip FK since connector may be in different tables depending on setup
