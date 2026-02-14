-- F071: Organization & Department Hierarchy
-- Add parent_id (self-referencing FK) and group_type to groups table

-- 1. Add parent_id column (nullable FK to self, restrict delete when children exist)
ALTER TABLE groups ADD COLUMN parent_id UUID REFERENCES groups(id) ON DELETE RESTRICT;

-- 2. Add group_type column with default for backward compatibility
ALTER TABLE groups ADD COLUMN group_type VARCHAR(30) NOT NULL DEFAULT 'security_group';

-- 3. Prevent direct self-reference (a group cannot be its own parent)
ALTER TABLE groups ADD CONSTRAINT ck_groups_no_self_parent CHECK (parent_id != id);

-- 4. Index for children lookup / hierarchy traversal
CREATE INDEX idx_groups_parent_id ON groups(tenant_id, parent_id);

-- 5. Index for type-filtered queries
CREATE INDEX idx_groups_type ON groups(tenant_id, group_type);

-- 6. Partial index for root group queries (groups with no parent)
CREATE INDEX idx_groups_root ON groups(tenant_id) WHERE parent_id IS NULL;
