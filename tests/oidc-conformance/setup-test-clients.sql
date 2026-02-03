-- Setup OIDC Conformance Test Clients
-- Run this against the xavyo-idp database before conformance testing

-- Test Tenant for conformance testing
INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
VALUES (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'OIDC Conformance Test Tenant',
    'oidc-conformance',
    'active',
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Primary Test Client (client_secret_basic)
INSERT INTO oauth_clients (
    id,
    tenant_id,
    client_id,
    client_secret_hash,
    name,
    client_type,
    grant_types,
    response_types,
    redirect_uris,
    token_endpoint_auth_method,
    pkce_required,
    created_at,
    updated_at
) VALUES (
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'conformance-test-client-1',
    -- Hash of 'conformance-test-secret-1' (use bcrypt in production)
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.rTSa4qz9tR3xGy',
    'OIDC Conformance Test Client 1',
    'confidential',
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['code'],
    ARRAY[
        'https://localhost:8443/test/a/xavyo-idp/callback',
        'https://localhost.emobix.co.uk:8443/test/a/xavyo-idp/callback'
    ],
    'client_secret_basic',
    false,
    NOW(),
    NOW()
) ON CONFLICT (client_id, tenant_id) DO UPDATE SET
    redirect_uris = EXCLUDED.redirect_uris,
    updated_at = NOW();

-- Secondary Test Client (for multi-client tests)
INSERT INTO oauth_clients (
    id,
    tenant_id,
    client_id,
    client_secret_hash,
    name,
    client_type,
    grant_types,
    response_types,
    redirect_uris,
    token_endpoint_auth_method,
    pkce_required,
    created_at,
    updated_at
) VALUES (
    'cccccccc-cccc-cccc-cccc-cccccccccccc',
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'conformance-test-client-2',
    -- Hash of 'conformance-test-secret-2'
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.rTSa4qz9tR3xGy',
    'OIDC Conformance Test Client 2',
    'confidential',
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['code'],
    ARRAY[
        'https://localhost:8443/test/a/xavyo-idp/callback',
        'https://localhost.emobix.co.uk:8443/test/a/xavyo-idp/callback'
    ],
    'client_secret_post',
    false,
    NOW(),
    NOW()
) ON CONFLICT (client_id, tenant_id) DO UPDATE SET
    redirect_uris = EXCLUDED.redirect_uris,
    updated_at = NOW();

-- Test User for authentication
INSERT INTO users (
    id,
    tenant_id,
    username,
    email,
    password_hash,
    email_verified,
    status,
    created_at,
    updated_at
) VALUES (
    'dddddddd-dddd-dddd-dddd-dddddddddddd',
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'conformance-test-user',
    'test@conformance.local',
    -- Hash of 'conformance-test-password'
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.rTSa4qz9tR3xGy',
    true,
    'active',
    NOW(),
    NOW()
) ON CONFLICT (email, tenant_id) DO NOTHING;

-- Output test credentials
SELECT 'Test Client 1:' AS info,
       'conformance-test-client-1' AS client_id,
       'conformance-test-secret-1' AS client_secret;
SELECT 'Test Client 2:' AS info,
       'conformance-test-client-2' AS client_id,
       'conformance-test-secret-2' AS client_secret;
SELECT 'Test User:' AS info,
       'conformance-test-user' AS username,
       'conformance-test-password' AS password;
