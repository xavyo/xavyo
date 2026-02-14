-- F036 Enhancement: Auto-skip certification items when assignment is deleted
-- This trigger marks pending certification items as 'skipped' when their
-- associated entitlement assignment is deleted (outside of the certification process).

-- ============================================================================
-- FUNCTION: Skip certification items when assignment is deleted
-- ============================================================================

CREATE OR REPLACE FUNCTION skip_cert_items_on_assignment_delete()
RETURNS TRIGGER AS $$
BEGIN
    -- Mark all pending certification items for this assignment as 'skipped'
    -- This handles the case where an assignment is deleted manually (not via certification revoke)
    UPDATE gov_certification_items
    SET
        status = 'skipped',
        decided_at = NOW(),
        updated_at = NOW()
    WHERE
        assignment_id = OLD.id
        AND status = 'pending';

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- TRIGGER: Before deleting an assignment, skip related certification items
-- ============================================================================

CREATE TRIGGER trigger_skip_cert_items_on_assignment_delete
    BEFORE DELETE ON gov_entitlement_assignments
    FOR EACH ROW
    EXECUTE FUNCTION skip_cert_items_on_assignment_delete();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON FUNCTION skip_cert_items_on_assignment_delete() IS
    'Automatically marks pending certification items as skipped when their associated assignment is deleted';

COMMENT ON TRIGGER trigger_skip_cert_items_on_assignment_delete ON gov_entitlement_assignments IS
    'Fires before assignment deletion to skip related pending certification items';
