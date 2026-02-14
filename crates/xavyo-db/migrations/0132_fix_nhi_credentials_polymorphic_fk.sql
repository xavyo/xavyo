-- Migration: 1085_fix_nhi_credentials_polymorphic_fk
-- Feature: F110 - Agent Credential Support Fix
-- Description: Removes hardcoded FK constraint to gov_service_accounts and adds
--              polymorphic validation trigger to support both service accounts and AI agents
--
-- PROBLEM 1: The gov_nhi_credentials table has a FK that only references gov_service_accounts,
--            but the nhi_type column allows 'agent' type credentials. This causes INSERT failures
--            when creating credentials for AI agents.
--
-- PROBLEM 2: The nhi_type column was VARCHAR(20) but the Rust model expects TEXT type.
--
-- SOLUTION: Replace FK constraint with a trigger that validates the nhi_id exists in the
--           correct table based on nhi_type value. Also change nhi_type to TEXT.

-- ============================================================================
-- STEP 0: Fix nhi_type column type (VARCHAR -> TEXT for SQLx compatibility)
-- ============================================================================

-- Change column type to TEXT (Rust model uses #[sqlx(type_name = "text")])
ALTER TABLE gov_nhi_credentials ALTER COLUMN nhi_type TYPE TEXT;

-- Re-add check constraint (was lost with type change)
ALTER TABLE gov_nhi_credentials
DROP CONSTRAINT IF EXISTS gov_nhi_credentials_nhi_type_check;

ALTER TABLE gov_nhi_credentials
ADD CONSTRAINT gov_nhi_credentials_nhi_type_check
CHECK (nhi_type IN ('service_account', 'agent'));

-- ============================================================================
-- STEP 1: Drop the existing FK constraint
-- ============================================================================

-- First, find and drop the FK constraint
-- The constraint is named gov_nhi_credentials_nhi_id_fkey (PostgreSQL auto-generated name)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'gov_nhi_credentials_nhi_id_fkey'
        AND table_name = 'gov_nhi_credentials'
    ) THEN
        ALTER TABLE gov_nhi_credentials
        DROP CONSTRAINT gov_nhi_credentials_nhi_id_fkey;
        RAISE NOTICE 'Dropped FK constraint gov_nhi_credentials_nhi_id_fkey';
    ELSE
        RAISE NOTICE 'FK constraint gov_nhi_credentials_nhi_id_fkey does not exist, skipping';
    END IF;
END $$;

-- ============================================================================
-- STEP 2: Create validation function for polymorphic nhi_id reference
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_nhi_credential_reference()
RETURNS TRIGGER AS $$
DECLARE
    ref_exists BOOLEAN := FALSE;
BEGIN
    -- Validate based on nhi_type
    IF NEW.nhi_type = 'service_account' THEN
        -- Check if nhi_id exists in gov_service_accounts
        SELECT EXISTS(
            SELECT 1 FROM gov_service_accounts
            WHERE id = NEW.nhi_id AND tenant_id = NEW.tenant_id
        ) INTO ref_exists;

        IF NOT ref_exists THEN
            RAISE EXCEPTION 'Service account with id % not found in tenant %',
                NEW.nhi_id, NEW.tenant_id;
        END IF;

    ELSIF NEW.nhi_type = 'agent' THEN
        -- Check if nhi_id exists in ai_agents
        SELECT EXISTS(
            SELECT 1 FROM ai_agents
            WHERE id = NEW.nhi_id AND tenant_id = NEW.tenant_id
        ) INTO ref_exists;

        IF NOT ref_exists THEN
            RAISE EXCEPTION 'AI agent with id % not found in tenant %',
                NEW.nhi_id, NEW.tenant_id;
        END IF;

    ELSE
        RAISE EXCEPTION 'Invalid nhi_type: %. Must be service_account or agent', NEW.nhi_type;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- STEP 3: Create trigger for INSERT and UPDATE
-- ============================================================================

-- Drop existing trigger if it exists (for idempotency)
DROP TRIGGER IF EXISTS trg_validate_nhi_credential_reference ON gov_nhi_credentials;

-- Create the validation trigger
CREATE TRIGGER trg_validate_nhi_credential_reference
    BEFORE INSERT OR UPDATE ON gov_nhi_credentials
    FOR EACH ROW
    EXECUTE FUNCTION validate_nhi_credential_reference();

-- ============================================================================
-- STEP 4: Add comments for documentation
-- ============================================================================

COMMENT ON FUNCTION validate_nhi_credential_reference() IS
'Validates that nhi_id references a valid entity in either gov_service_accounts (for service_account type) or ai_agents (for agent type). Replaces the original FK constraint to support polymorphic references.';

COMMENT ON TRIGGER trg_validate_nhi_credential_reference ON gov_nhi_credentials IS
'Ensures referential integrity for polymorphic NHI credential references (F110).';

-- ============================================================================
-- STEP 5: Create index for nhi_id lookups (since FK index is gone)
-- ============================================================================

-- The FK constraint provided an implicit index, so we add one explicitly
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_nhi_id
ON gov_nhi_credentials(nhi_id);

-- Composite index for lookup by tenant and nhi
CREATE INDEX IF NOT EXISTS idx_gov_nhi_credentials_tenant_nhi
ON gov_nhi_credentials(tenant_id, nhi_id);

-- ============================================================================
-- VERIFICATION
-- ============================================================================

DO $$
BEGIN
    -- Verify trigger exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_validate_nhi_credential_reference'
    ) THEN
        RAISE EXCEPTION 'Migration failed: trigger not created';
    END IF;

    -- Verify function exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'validate_nhi_credential_reference'
    ) THEN
        RAISE EXCEPTION 'Migration failed: function not created';
    END IF;

    RAISE NOTICE 'Migration 1085 completed successfully: polymorphic NHI credential FK support enabled';
END $$;
