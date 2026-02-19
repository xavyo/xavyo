-- Add freshness tracking columns to nhi_tools for MCP discovery sync-check.
ALTER TABLE nhi_tools ADD COLUMN IF NOT EXISTS last_discovered_at TIMESTAMPTZ;
ALTER TABLE nhi_tools ADD COLUMN IF NOT EXISTS discovery_source TEXT;
