-- Fix FK constraint on gov_persona_audit_events to allow archetype/persona deletion.
-- Audit events are immutable records; setting the FK to NULL preserves the audit trail
-- while allowing the referenced archetype or persona to be deleted.

-- Drop existing FK constraints and recreate with ON DELETE SET NULL
ALTER TABLE gov_persona_audit_events
    DROP CONSTRAINT IF EXISTS gov_persona_audit_events_archetype_id_fkey;

ALTER TABLE gov_persona_audit_events
    ADD CONSTRAINT gov_persona_audit_events_archetype_id_fkey
    FOREIGN KEY (archetype_id) REFERENCES gov_persona_archetypes(id) ON DELETE SET NULL;

ALTER TABLE gov_persona_audit_events
    DROP CONSTRAINT IF EXISTS gov_persona_audit_events_persona_id_fkey;

ALTER TABLE gov_persona_audit_events
    ADD CONSTRAINT gov_persona_audit_events_persona_id_fkey
    FOREIGN KEY (persona_id) REFERENCES gov_personas(id) ON DELETE SET NULL;

-- Also relax the CHECK constraint since both can now be NULL after deletion
ALTER TABLE gov_persona_audit_events
    DROP CONSTRAINT IF EXISTS chk_audit_reference;
