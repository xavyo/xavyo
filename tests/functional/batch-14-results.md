# Batch 14: Features 202-205 — API Key Identity, NHI Permissions, Protocol Migration

| Test ID | Result | Details |
|---------|--------|---------|
| TC-F202-001 | PASS | Created admin API key id=a2e206f9-d845-48ad-a512-d450d46b7e94 |
| TC-F202-002 | PASS | Admin key can access /admin/users (role inherited) |
| TC-F202-003 | PASS | Admin key can access /nhi |
| TC-F202-004 | PASS | Created scoped key id=2f982c60-ccbf-4f69-b09a-f420cb6a6a95 scope=[nhi:read] |
| TC-F202-005 | PASS | Scoped key GET /nhi allowed |
| TC-F202-006 | PASS | Scoped key POST /nhi/agents blocked (403) |
| TC-F202-007 | PASS | Scoped key GET /admin/users blocked (out of scope) |
| TC-F202-008 | PASS | Empty scope key has full access to /admin/groups |
| TC-F202-009 | PASS | Created wildcard NHI key id=172ab9aa-2746-4154-91cc-fc2ea71bef97 scope=[nhi:*] |
| TC-F202-010 | PASS | nhi:* key can POST /nhi/agents, agent=27cbdea1-cc5a-4af5-880f-0154b67de2c9 |
| TC-F202-011 | PASS | nhi:* key blocked from /admin/users (403) |
| TC-F202-012 | PASS | User key created, inherits user role |
| TC-F202-013 | PASS | Invalid API key returns 401 |
| TC-F202-014 | PASS | Created resource-scoped key [nhi:agents:read] |
| TC-F202-015 | PASS | nhi:agents:read key can GET /nhi/agents |
| TC-F202-016 | PASS | nhi:agents:read key blocked from /nhi/tools (403) |
| TC-F204-UP-001 | PASS | Granted 'use' permission to user on agent |
| TC-F204-UP-002 | PASS | Granted 'manage' permission to user on tool |
| TC-F204-UP-003 | PASS | Granted 'admin' permission to user on SA |
| TC-F204-UP-004 | PASS | Listed 1 user(s) with access to agent |
| TC-F204-UP-005 | PASS | User has access to 3 NHI(s) |
| TC-F204-UP-006 | PASS | Duplicate grant handled (code=201) |
| TC-F204-UP-007 | PASS | Invalid permission type rejected (400) |
| TC-F204-UP-008 | PASS | Grant on nonexistent NHI returns 404 |
| TC-F204-UP-009 | PASS | Non-admin grant rejected (403) |
| TC-F204-UP-010 | PASS | Grant with expiry accepted |
| TC-F204-UP-011 | PASS | Revoked 'admin' permission from SA |
| TC-F204-UP-012 | PASS | Revoke nonexistent permission handled (404) |
| TC-F204-NP-001 | PASS | Granted 'call' permission agent→target |
| TC-F204-NP-002 | PASS | Granted 'delegate' permission agent→target |
| TC-F204-NP-003 | PASS | Granted 'call' permission agent→tool |
| TC-F204-NP-004 | PASS | Self-referential grant rejected (400) |
| TC-F204-NP-005 | PASS | Agent has 3 callee(s) |
| TC-F204-NP-006 | PASS | Target has 2 caller(s) |
| TC-F204-NP-007 | PASS | Granted call with rate limit max_calls=100 |
| TC-F204-NP-008 | PASS | Revoked 'delegate' permission |
| TC-F204-NP-009 | PASS | Non-admin NHI→NHI grant rejected (403) |
| TC-F204-NP-010 | PASS | Grant with fake source NHI handled (404) |
| TC-F204-ENF-001 | PASS | Non-admin /nhi list returned 2 filtered NHI(s) |
| TC-F204-ENF-002 | PASS | User with 'use' permission can GET agent |
| TC-F204-ENF-003 | PASS | User without permission blocked from agent (403) |
| TC-F204-ENF-004 | PASS | Admin can access NHI without explicit permission |
| TC-F204-ENF-005 | PASS | User with 'use' cannot suspend (requires manage) |
| TC-F204-ENF-006 | PASS | User with 'manage' can issue credentials |
| TC-F204-ENF-007 | PASS | Non-admin /nhi/agents returns 0 filtered agent(s) |
| TC-F204-ENF-008 | PASS | Unauthenticated /nhi returns 401 |
| TC-F205-MCP-001 | PASS | GET /mcp/tools returns 200 |
| TC-F205-MCP-002 | PASS | MCP tools response is valid JSON ("object") |
| TC-F205-MCP-003 | PASS | GET /mcp/tools unauthenticated returns 401 |
| TC-F205-MCP-004 | PASS | MCP call nonexistent tool returns 404 |
| TC-F205-A2A-001 | PASS | GET /a2a/tasks returns 200 |
| TC-F205-A2A-002 | PASS | GET /a2a/tasks unauthenticated returns 401 |
| TC-F205-A2A-003 | PASS | Created A2A task id=6e458922-bb29-42dd-ab90-bb9fd1f19087 |
| TC-F205-A2A-004 | PASS | Got A2A task status: pending |
| TC-F205-A2A-005 | PASS | Cancelled A2A task |
| TC-F205-A2A-006 | PASS | Get nonexistent A2A task returns 404 |
| TC-F205-A2A-007 | PASS | Cancel nonexistent A2A task returns 404 |
| TC-F205-A2A-008 | PASS | A2A task list with state filter works |
| TC-F205-DISC-001 | PASS | AgentCard returned for perm-test-agent-1770762232 |
| TC-F205-DISC-002 | PASS | AgentCard has name=perm-test-agent-1770762232 type=null |
| TC-F205-DISC-003 | PASS | AgentCard for nonexistent agent returns 404 |
| TC-F205-DISC-004 | PASS | Discovery is public (no auth header needed) |
| TC-F205-DISC-005 | PASS | Discovery for tool NHI returns 404 (agents only) |
| TC-F205-DISC-006 | PASS | Invalid UUID in discovery returns 400 |
| TC-F205-LEGACY-001 | PASS | Legacy /agents endpoint returns 404 |
| TC-F205-LEGACY-002 | PASS | Legacy /agents/tools returns 404 |
