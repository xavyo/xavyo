-- Migration: 1001_request_catalog.sql
-- Feature: F-062 Self-Service Request Catalog
-- Description: Creates catalog_item_type enum, catalog_categories, catalog_items,
--              request_carts, and request_cart_items tables with RLS and indexes

-- ============================================================================
-- ENUM TYPE
-- ============================================================================

CREATE TYPE catalog_item_type AS ENUM ('role', 'entitlement', 'resource');

-- ============================================================================
-- CATALOG CATEGORIES
-- ============================================================================

CREATE TABLE catalog_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES catalog_categories(id) ON DELETE SET NULL,
    icon VARCHAR(100),
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- No duplicate names at same level within tenant
    CONSTRAINT uq_catalog_categories_name UNIQUE (tenant_id, name, parent_id),
    -- Prevent self-reference
    CONSTRAINT chk_catalog_categories_no_self_ref CHECK (parent_id != id)
);

-- Index for hierarchical queries
CREATE INDEX idx_catalog_categories_tenant_parent ON catalog_categories(tenant_id, parent_id);

-- ============================================================================
-- CATALOG ITEMS
-- ============================================================================

CREATE TABLE catalog_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    category_id UUID REFERENCES catalog_categories(id) ON DELETE SET NULL,
    item_type catalog_item_type NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    reference_id UUID, -- FK to gov_roles or gov_entitlements (enforced in application)
    requestability_rules JSONB NOT NULL DEFAULT '{}',
    form_fields JSONB NOT NULL DEFAULT '[]',
    tags TEXT[] NOT NULL DEFAULT '{}',
    icon VARCHAR(100),
    enabled BOOLEAN NOT NULL DEFAULT true,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique names per tenant
    CONSTRAINT uq_catalog_items_name UNIQUE (tenant_id, name),
    -- Role and entitlement items must have reference_id
    CONSTRAINT chk_catalog_items_reference CHECK (
        (item_type IN ('role', 'entitlement') AND reference_id IS NOT NULL)
        OR item_type = 'resource'
    )
);

-- Index for browsing enabled items
CREATE INDEX idx_catalog_items_tenant_enabled ON catalog_items(tenant_id, enabled) WHERE enabled = true;

-- Index for category filtering
CREATE INDEX idx_catalog_items_category ON catalog_items(tenant_id, category_id);

-- Index for type filtering
CREATE INDEX idx_catalog_items_type ON catalog_items(tenant_id, item_type);

-- GIN index for full-text search on name, description, and tags
CREATE INDEX idx_catalog_items_search ON catalog_items
    USING GIN (to_tsvector('english', name || ' ' || COALESCE(description, '') || ' ' || array_to_string(tags, ' ')));

-- ============================================================================
-- REQUEST CARTS
-- ============================================================================

CREATE TABLE request_carts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    beneficiary_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One cart per requester-beneficiary pair (NULL beneficiary = self)
    CONSTRAINT uq_request_carts_pair UNIQUE (tenant_id, requester_id, beneficiary_id)
);

-- Index for requester lookup
CREATE INDEX idx_request_carts_requester ON request_carts(tenant_id, requester_id);

-- Index for beneficiary lookup (only for non-null beneficiaries)
CREATE INDEX idx_request_carts_beneficiary ON request_carts(tenant_id, beneficiary_id)
    WHERE beneficiary_id IS NOT NULL;

-- ============================================================================
-- REQUEST CART ITEMS
-- ============================================================================

CREATE TABLE request_cart_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cart_id UUID NOT NULL REFERENCES request_carts(id) ON DELETE CASCADE,
    catalog_item_id UUID NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    parameters JSONB NOT NULL DEFAULT '{}',
    form_values JSONB NOT NULL DEFAULT '{}',
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- No exact duplicates (same item with same parameters)
    CONSTRAINT uq_request_cart_items_no_dup UNIQUE (cart_id, catalog_item_id, parameters)
);

-- Index for cart item lookup
CREATE INDEX idx_request_cart_items_cart ON request_cart_items(tenant_id, cart_id);

-- ============================================================================
-- ROW-LEVEL SECURITY (RLS)
-- ============================================================================

-- catalog_categories RLS
ALTER TABLE catalog_categories ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_catalog_categories ON catalog_categories
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- catalog_items RLS
ALTER TABLE catalog_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_catalog_items ON catalog_items
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- request_carts RLS
ALTER TABLE request_carts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_request_carts ON request_carts
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- request_cart_items RLS
ALTER TABLE request_cart_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_request_cart_items ON request_cart_items
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS FOR updated_at
-- ============================================================================

CREATE TRIGGER trg_catalog_categories_updated_at
    BEFORE UPDATE ON catalog_categories
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_catalog_items_updated_at
    BEFORE UPDATE ON catalog_items
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_request_carts_updated_at
    BEFORE UPDATE ON request_carts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
