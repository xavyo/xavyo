-- Migration 1203: Migrate A2A tasks FKs from ai_agents to nhi_identities
-- Feature 205: Protocol Migration

-- Step 1: Add new nullable FK columns referencing nhi_identities
ALTER TABLE a2a_tasks ADD COLUMN IF NOT EXISTS source_nhi_id UUID REFERENCES nhi_identities(id) ON DELETE SET NULL;
ALTER TABLE a2a_tasks ADD COLUMN IF NOT EXISTS target_nhi_id UUID REFERENCES nhi_identities(id) ON DELETE SET NULL;

-- Step 2: Attempt data migration - match old agent IDs against NHI records by name
-- This handles the case where agents were imported into the NHI system
UPDATE a2a_tasks t
SET source_nhi_id = n.id
FROM ai_agents a
JOIN nhi_identities n ON n.tenant_id = a.tenant_id AND n.name = a.name AND n.nhi_type = 'agent'
WHERE t.source_agent_id = a.id
  AND t.source_nhi_id IS NULL;

UPDATE a2a_tasks t
SET target_nhi_id = n.id
FROM ai_agents a
JOIN nhi_identities n ON n.tenant_id = a.tenant_id AND n.name = a.name AND n.nhi_type = 'agent'
WHERE t.target_agent_id = a.id
  AND t.target_nhi_id IS NULL;

-- Step 3: Drop old FK columns
ALTER TABLE a2a_tasks DROP COLUMN IF EXISTS source_agent_id;
ALTER TABLE a2a_tasks DROP COLUMN IF EXISTS target_agent_id;

-- Step 4: Add indexes for new columns
CREATE INDEX IF NOT EXISTS idx_a2a_tasks_source_nhi ON a2a_tasks (tenant_id, source_nhi_id);
CREATE INDEX IF NOT EXISTS idx_a2a_tasks_target_nhi ON a2a_tasks (tenant_id, target_nhi_id);
