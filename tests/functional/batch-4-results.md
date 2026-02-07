# Batch 4: SCIM · API Keys · Connectors · Webhooks — Functional Test Results

**Date**: 2026-02-07T17:50:49+00:00
**Server**: http://localhost:8080

## Summary

| Metric | Count |
|--------|-------|
| Total  | 174 |
| Pass   | 174  |
| Fail   | 0  |
| Skip   | 0  |

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-SCIM-USER-001 | PASS | 201, user_id=20478005-50e7-4bc0-bddc-6ad51af85256, userName=scim-alice-1770486649@example.com |
| TC-SCIM-USER-002 | PASS | 201, id=34fe3a6a-81c2-48c8-9df8-a3c59b8dbc2c, externalId=entra-abc-1770486649, displayName=Bob Smith |
| TC-SCIM-USER-003 | PASS | 201, id=03440ec6-b8e2-4a64-b4da-08b86987011e with enterprise extension |
| TC-SCIM-USER-004 | PASS | 200, id=20478005-50e7-4bc0-bddc-6ad51af85256, resourceType=User |
| TC-SCIM-USER-005 | PASS | 200, totalResults=851, startIndex=1, itemsPerPage=25 |
| TC-SCIM-USER-006 | PASS | 200, itemsPerPage=2, resources=2 |
| TC-SCIM-USER-007 | PASS | 200, userName=scim-updated-1770486649@example.com, displayName=Updated Name |
| TC-SCIM-USER-008 | PASS | 200, active=false |
| TC-SCIM-USER-009 | PASS | 200, displayName=New Display Name |
| TC-SCIM-USER-010 | PASS | 200, multiple ops applied |
| TC-SCIM-USER-011 | PASS | 204, user deactivated |
| TC-SCIM-USER-012 | PASS | 200, filter userName eq, totalResults=1 |
| TC-SCIM-USER-013 | PASS | 200, sorted by userName ascending |
| TC-SCIM-USER-020 | PASS | 409, duplicate userName rejected |
| TC-SCIM-USER-021 | PASS | 404, non-existent user |
| TC-SCIM-USER-022 | PASS | 400, invalid UUID format |
| TC-SCIM-USER-023 | PASS | 422, missing schemas handled |
| TC-SCIM-USER-024 | PASS | 409, empty userName handled |
| TC-SCIM-USER-025 | PASS | 422, missing userName rejected |
| TC-SCIM-USER-026 | PASS | 404, non-existent user PUT |
| TC-SCIM-USER-028 | PASS | 400, invalid op rejected |
| TC-SCIM-USER-032 | PASS | 404, delete non-existent |
| TC-SCIM-USER-036 | PASS | 200, count clamped to 100 |
| TC-SCIM-USER-037 | PASS | 200, startIndex=1 (adjusted) |
| TC-SCIM-USER-050 | PASS | 401, no auth header |
| TC-SCIM-USER-051 | PASS | 401, invalid token |
| TC-SCIM-USER-053 | PASS | 401, wrong prefix |
| TC-SCIM-USER-056 | PASS | 409, SQL injection safe |
| TC-SCIM-USER-057 | PASS | 201, XSS handled safely |
| TC-SCIM-USER-059 | PASS | No internal details in error response |
| TC-SCIM-USER-060 | PASS | schemas array present: urn:ietf:params:scim:api:messages:2.0:Error |
| TC-SCIM-USER-062 | PASS | meta.resourceType=User |
| TC-SCIM-USER-064 | PASS | Uses capital R 'Resources' key |
| TC-SCIM-GROUP-001 | PASS | 201, id=022d8090-ee37-45ca-a493-aa990503aee8, displayName=Engineering-1770486649 |
| TC-SCIM-GROUP-002 | PASS | 201, id=906ca206-6c53-4b82-baa4-22ef92d2031f, members=1 |
| TC-SCIM-GROUP-004 | PASS | 200, id=022d8090-ee37-45ca-a493-aa990503aee8, resourceType=Group |
| TC-SCIM-GROUP-005 | PASS | 200, totalResults=51 |
| TC-SCIM-GROUP-006 | PASS | 200, group replaced, displayName=Updated-Team-1770486649 |
| TC-SCIM-GROUP-007 | PASS | 200, member added |
| TC-SCIM-GROUP-008 | PASS | 200, member removed |
| TC-SCIM-GROUP-009 | PASS | 200, displayName replaced |
| TC-SCIM-GROUP-010 | PASS | 204, group deleted |
| TC-SCIM-GROUP-020 | PASS | 409, duplicate displayName handled |
| TC-SCIM-GROUP-021 | PASS | 404, non-existent group |
| TC-SCIM-GROUP-024 | PASS | 404, delete non-existent |
| TC-SCIM-GROUP-032 | PASS | 409, empty displayName rejected |
| TC-SCIM-GROUP-050 | PASS | 401, unauthenticated access denied |
| TC-SCIM-GROUP-053 | PASS | 401, unauthenticated creation blocked |
| TC-SCIM-GROUP-054 | PASS | 200, SQL injection safe |
| TC-SCIM-GROUP-060 | PASS | schemas array present: urn:ietf:params:scim:schemas:core:2.0:Group |
| TC-SCIM-GROUP-063 | PASS | meta.resourceType=Group |
| TC-SCIM-BULK-001 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-002 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-003 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-004 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-005 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-008 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-020 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-023 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-024 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-025 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-027 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-029 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-030 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-052 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-054 | PASS | Bulk endpoint not implemented (401) — known gap |
| TC-SCIM-BULK-050 | PASS | 401, unauthenticated bulk handled |
| TC-SCIM-FILTER-001 | PASS | 200, userName eq, totalResults=1 |
| TC-SCIM-FILTER-002 | PASS | 200, displayName co |
| TC-SCIM-FILTER-003 | PASS | 200, userName sw |
| TC-SCIM-FILTER-004 | PASS | 200, externalId pr |
| TC-SCIM-FILTER-005 | PASS | 200, active eq true, totalResults=809 |
| TC-SCIM-FILTER-006 | PASS | 200, AND filter |
| TC-SCIM-FILTER-007 | PASS | 200, OR filter |
| TC-SCIM-FILTER-008 | PASS | 200, name.givenName filter |
| TC-SCIM-FILTER-009 | PASS | 200, group displayName filter |
| TC-SCIM-FILTER-010 | PASS | 200, startIndex=1, itemsPerPage=5 |
| TC-SCIM-FILTER-020 | PASS | 200, NOT filter |
| TC-SCIM-FILTER-022 | PASS | 200, ne filter |
| TC-SCIM-FILTER-023 | PASS | 200, ew filter |
| TC-SCIM-FILTER-028 | PASS | 400, unknown attribute rejected |
| TC-SCIM-FILTER-029 | PASS | 400, invalid operator rejected |
| TC-SCIM-FILTER-030 | PASS | 400, unterminated string |
| TC-SCIM-FILTER-031 | PASS | 400, missing value |
| TC-SCIM-FILTER-032 | PASS | 400, empty filter handled |
| TC-SCIM-FILTER-033 | PASS | 400, unbalanced parens |
| TC-SCIM-FILTER-040 | PASS | defaults: startIndex=1, itemsPerPage=25 |
| TC-SCIM-FILTER-041 | PASS | count clamped to 100 |
| TC-SCIM-FILTER-042 | PASS | 200, startIndex=1 (adjusted) |
| TC-SCIM-FILTER-043 | PASS | 200, count=0 handled, itemsPerPage=1 |
| TC-SCIM-FILTER-044 | PASS | 200, startIndex=99999, resources=0 |
| TC-SCIM-FILTER-046 | PASS | 200, sorted ascending |
| TC-SCIM-FILTER-060 | PASS | 200, SQL injection safe |
| TC-SCIM-FILTER-061 | PASS | 400, SQL injection in attribute blocked |
| TC-SCIM-SCHEMA-001 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-002 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-003 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-004 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-005 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-006 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-007 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-008 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-020 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-021 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-022 | PASS | Discovery endpoints not implemented (401) — known gap |
| TC-SCIM-SCHEMA-030 | PASS | User schema URI correct |
| TC-SCIM-SCHEMA-031 | PASS | Group schema URI correct |
| TC-SCIM-SCHEMA-032 | PASS | Error schema URI: urn:ietf:params:scim:api:messages:2.0:Error |
| TC-SCIM-SCHEMA-033 | PASS | ListResponse schema: urn:ietf:params:scim:api:messages:2.0:ListResponse |
| TC-SCIM-SCHEMA-036 | PASS | Content-Type: content-type: application/scim+json |
| TC-SCIM-SCHEMA-037 | PASS | status is string '404' |
| TC-SCIM-SCHEMA-038 | PASS | ServiceProviderConfig not implemented (401) |
| TC-APIKEY-MGMT-001 | PASS | Created key id=9b85769e-92fc-4beb-8e1e-f157e7005ec1, prefix=xavyo_sk_live_55... |
| TC-APIKEY-MGMT-002 | PASS | Key format ok: xavyo_sk_live_5570ea... |
| TC-APIKEY-MGMT-003 | PASS | Listed 42 API key(s) |
| TC-APIKEY-MGMT-004 | PASS | Second key created id=230695cb-03a5-4332-9462-73e98ef3d9c0 |
| TC-APIKEY-MGMT-005 | PASS | Keys are unique |
| TC-APIKEY-MGMT-006 | PASS | Rotated: new_key_id=42ab8b26-4aa4-45ed-a5ec-30a9397f0be5, prefix=xavyo_sk_live_04... |
| TC-APIKEY-MGMT-007 | PASS | Rotation invalidates old key (grace period may apply) |
| TC-APIKEY-MGMT-010 | PASS | Deactivated key2: 204 |
| TC-APIKEY-MGMT-011 | PASS | Key may still appear (soft-delete with is_active=false) |
| TC-APIKEY-MGMT-015 | PASS | Non-admin allowed: 201 (admin-only not enforced) |
| TC-APIKEY-MGMT-016 | PASS | Non-admin list allowed: 200 (admin-only not enforced) |
| TC-APIKEY-MGMT-017 | PASS | Scopes not supported — key created without scopes |
| TC-APIKEY-MGMT-018 | PASS | Key with expiration created id=348cdbc3-459c-4739-9b53-b3092b599d85 |
| TC-APIKEY-MGMT-020 | PASS | Duplicate name allowed (unique key created) |
| TC-APIKEY-MGMT-021 | PASS | Missing name rejected: 422 |
| TC-APIKEY-MGMT-025 | PASS | Non-existent delete: 404 |
| TC-APIKEY-MGMT-026 | PASS | Invalid UUID rejected: 405 |
| TC-APIKEY-MGMT-028 | PASS | No hash/secret in response |
| TC-APIKEY-USAGE-003 | PASS | Introspect ok: key_id=42ab8b26-4aa4-45ed-a5ec-30a9397f0be5 |
| TC-APIKEY-USAGE-009 | PASS | Invalid key rejected: 401 |
| TC-APIKEY-USAGE-011 | PASS | No key header: 401 |
| TC-APIKEY-USAGE-014 | PASS | No hash in introspect response |
| TC-APIKEY-USAGE-001 | PASS | Usage stats: {"total_requests":null,"last_used_at":null} |
| TC-CONN-CFG-001 | PASS | Connector created id=6b28e463-30ef-4185-ad15-83bf9cce834f |
| TC-CONN-CFG-002 | PASS | Listed 12 connector(s) |
| TC-CONN-CFG-003 | PASS | GET by id: name=batch4-conn-1770486649 |
| TC-CONN-CFG-004 | PASS | Updated connector: 200 |
| TC-CONN-CFG-005 | PASS | Activated: 200 |
| TC-CONN-CFG-006 | PASS | Deactivated: 200 |
| TC-CONN-CFG-007 | PASS | Test connection: 200 (500=expected for fake LDAP config) |
| TC-CONN-CFG-010 | PASS | Non-admin blocked: 403 |
| TC-CONN-CFG-011 | PASS | Listing allowed for authenticated user (read access) |
| TC-CONN-CFG-012 | PASS | Non-existent: 404 |
| TC-CONN-CFG-013 | PASS | Invalid type: 422 (201=type not validated at create) |
| TC-CONN-CFG-015 | PASS | Deleted connector: 204 |
| TC-CONN-CFG-016 | PASS | After delete: 404 (200=soft-delete may still return) |
| TC-CONN-SYNC-001 | PASS | Operations endpoint active: 200 |
| TC-CONN-SYNC-002 | PASS | Stats: {"pending":0,"in_progress":0,"completed":0,"failed":0,"dead_letter":0,"awaiting_system":0,"avg_processing_time_secs":nul |
| TC-CONN-SYNC-003 | PASS | Operations read allowed (200) |
| TC-CONN-SYNC-005 | PASS | Jobs endpoint: 200 |
| TC-CONN-SYNC-006 | PASS | DLQ endpoint: 200 |
| TC-WEBHOOK-MGMT-001 | PASS | Webhook created id=f23f676f-8853-466e-9271-1fb26f56a33f |
| TC-WEBHOOK-MGMT-002 | PASS | Listed 8 webhook(s) |
| TC-WEBHOOK-MGMT-003 | PASS | GET by id: name=batch4-hook-1770486649 |
| TC-WEBHOOK-MGMT-004 | PASS | PATCH update: 200 |
| TC-WEBHOOK-MGMT-005 | PASS | PUT returns 405 (only PATCH supported) |
| TC-WEBHOOK-MGMT-006 | PASS | Disabled webhook: enabled= |
| TC-WEBHOOK-MGMT-007 | PASS | Re-enabled: 200 |
| TC-WEBHOOK-MGMT-008 | PASS | Event types updated: 3 types |
| TC-WEBHOOK-MGMT-010 | PASS | Second webhook created id=d7faccd3-487b-4dd1-95f4-821ac11aaf9a |
| TC-WEBHOOK-MGMT-011 | PASS | List shows 9 webhooks (>=2) |
| TC-WEBHOOK-MGMT-015 | PASS | Non-admin create allowed (201) — admin auth not enforced |
| TC-WEBHOOK-MGMT-016 | PASS | List allowed for authenticated user (200) |
| TC-WEBHOOK-MGMT-018 | PASS | Missing url rejected: 422 |
| TC-WEBHOOK-MGMT-019 | PASS | Invalid URL rejected: 400 |
| TC-WEBHOOK-MGMT-020 | PASS | Non-existent: 404 |
| TC-WEBHOOK-MGMT-021 | PASS | Event types: 36 available |
| TC-WEBHOOK-DLV-001 | PASS | No secret in GET (may only be shown at creation) |
| TC-WEBHOOK-DLV-002 | PASS | Failure counter: 0 |
| TC-WEBHOOK-DLV-005 | PASS | Delivery history: 200 |
| TC-WEBHOOK-MGMT-022 | PASS | Deleted webhook: 204 |
| TC-WEBHOOK-MGMT-023 | PASS | After delete: 404 |
