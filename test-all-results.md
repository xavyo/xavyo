# XAVYO IDP - Comprehensive API Test Results

| # | Section | Test | Status | HTTP | Details |
|---|---------|------|--------|------|---------|
| 1 | Setup | Register admin user | PASS | 201 | id=8c896230-79bd-4f7b-912a-0d6bfdd786d6 |
| 2 | Setup | Login admin user | PASS | 200 | token obtained |
| 3 | Health | GET /health | PASS | 200 |  |
| 4 | Health | GET /livez | PASS | 200 |  |
| 5 | Health | GET /readyz | PASS | 200 |  |
| 6 | Health | GET /healthz | PASS | 200 |  |
| 7 | Health | GET /startupz | PASS | 200 |  |
| 8 | Health | GET /metrics (prometheus) | PASS | 200 | contains http_requests_total |
| 9 | OIDC | GET /.well-known/openid-configuration | PASS | 200 | has issuer |
| 10 | OIDC | GET /.well-known/jwks.json | PASS | 200 | has keys |
| 11 | Auth | Token refresh | PASS | 200 | new token issued |
| 12 | Auth | Token introspect (unknown client=401) | PASS | 401 | auth correctly required |
| 13 | Me | GET /me/profile | PASS | 200 | profile returned |
| 14 | Me | GET /me/sessions | PASS | 200 |  |
| 15 | Me | GET /me/security | PASS | 200 |  |
| 16 | Me | GET /me/devices | PASS | 200 |  |
| 17 | Me | GET /me/mfa | PASS | 200 |  |
| 18 | Users | List users | PASS | 200 |  |
| 19 | Users | Get user by ID | PASS | 200 | email matches |
| 20 | Users | Update user (set username) | PASS | 200 |  |
| 21 | Users | Get user after update | PASS | 200 | user retrieved |
| 22 | Users | Get non-existent user (404) | PASS | 404 |  |
| 23 | Groups | List groups | PASS | 200 |  |
| 24 | Groups | List root groups | PASS | 200 |  |
| 25 | AttrDef | List attribute definitions | PASS | 200 |  |
| 26 | AttrDef | Create attribute definition | PASS | 201 | id=8e3fac11-35ed-459d-bd72-63ae88f44c3c |
| 27 | AttrDef | Get attribute definition | PASS | 200 |  |
| 28 | Gov-App | Create application | PASS | 201 | id=99faeedc-322f-4559-92dd-482f35abe53a |
| 29 | Gov-App | List applications (contains created) | PASS | 200 |  |
| 30 | Gov-App | Get application by ID | PASS | 200 | name matches |
| 31 | Gov-App | Update application | PASS | 200 |  |
| 32 | Gov-Ent | Create entitlement | PASS | 201 | id=760e5f49-3d54-4012-98b1-e9d1d90ef8ae |
| 33 | Gov-Ent | Create second entitlement | PASS | 201 | id=16945018-7cf1-416c-97c6-4f0c10b15b13 |
| 34 | Gov-Ent | List entitlements | PASS | 200 |  |
| 35 | Gov-Ent | Get entitlement by ID | PASS | 200 |  |
| 36 | Gov-Ent | Set entitlement owner | PASS | 200 |  |
| 37 | Gov-Assign | Create assignment | PASS | 201 | id=73704485-d909-41cb-9c08-46a1e2a23faa |
| 38 | Gov-Assign | List assignments | PASS | 200 |  |
| 39 | Gov-Assign | Get assignment | PASS | 200 |  |
| 40 | Gov-Assign | Get effective access | PASS | 200 |  |
| 41 | Gov-Assign | Check entitlement access | PASS | 200 |  |
| 42 | Gov-Role | Create role | PASS | 200 | id=2a790c83-f2f4-490d-a3c0-1c265e322dd5 |
| 43 | Gov-Role | List roles | PASS | 200 |  |
| 44 | Gov-Role | Get role tree | PASS | 200 |  |
| 45 | Gov-Role | Get role by ID | PASS | 200 |  |
| 46 | Gov-Role | Update role | PASS | 200 |  |
| 47 | Gov-Role | Get ancestors | PASS | 200 |  |
| 48 | Gov-Role | Get descendants | PASS | 200 |  |
| 49 | Gov-Role | Get role impact | PASS | 200 |  |
| 50 | Gov-Role | Create child role | PASS | 200 | id=ba3f6d5d-1aaa-46ef-9ac0-575524658ea9 |
| 51 | Gov-Role | Create role-entitlement mapping | PASS | 201 |  |
| 52 | Gov-Role | List role-entitlements | PASS | 200 |  |
| 53 | Gov-SoD | Create SoD rule | PASS | 201 | id=a91c0f96-55ae-4fc2-a2ab-5c469cd3c82c |
| 54 | Gov-SoD | List SoD rules | PASS | 200 |  |
| 55 | Gov-SoD | Get SoD rule | PASS | 200 |  |
| 56 | Gov-SoD | Enable SoD rule | PASS | 200 |  |
| 57 | Gov-SoD | SoD pre-flight check | PASS | 200 |  |
| 58 | Gov-SoD | Scan SoD rule | PASS | 200 |  |
| 59 | Gov-SoD | List SoD violations | PASS | 200 |  |
| 60 | Gov-SoD | List SoD exemptions | PASS | 200 |  |
| 61 | Gov-AR | Create access request | PASS | 201 | id=e384bd93-9ac0-43a7-ae7d-c06996d85932 |
| 62 | Gov-AR | List my requests | PASS | 200 |  |
| 63 | Gov-AR | Get access request | PASS | 200 |  |
| 64 | Gov-AR | List pending approvals | PASS | 200 |  |
| 65 | Gov-Cert | Create certification campaign | PASS | 201 | id=dce997f5-3810-48bf-928f-9cd95a67c811 |
| 66 | Gov-Cert | List campaigns | PASS | 200 |  |
| 67 | Gov-Cert | Get campaign | PASS | 200 |  |
| 68 | Gov-Risk | List risk factors | PASS | 200 |  |
| 69 | Gov-Risk | Create risk factor | PASS | 201 | id=ed20828d-209e-46c8-9270-cf58e3922482 |
| 70 | Gov-Risk | List risk scores | PASS | 200 |  |
| 71 | Gov-Risk | List risk alerts | PASS | 200 |  |
| 72 | Gov-Risk | Risk alert summary | PASS | 200 |  |
| 73 | Gov-Risk | List peer groups | PASS | 200 |  |
| 74 | Gov-Risk | List risk thresholds | PASS | 200 |  |
| 75 | Gov-Mining | List mining jobs | PASS | 200 |  |
| 76 | Gov-Mining | List mining metrics | PASS | 200 |  |
| 77 | Gov-Report | List report templates | PASS | 200 |  |
| 78 | Gov-Report | List reports | PASS | 200 |  |
| 79 | Gov-Report | List report schedules | PASS | 200 |  |
| 80 | Gov-LC | List lifecycle configs | PASS | 200 |  |
| 81 | Gov-LC | List lifecycle events | PASS | 200 |  |
| 82 | Gov-LC | List lifecycle actions | PASS | 200 |  |
| 83 | Gov-LC | List access snapshots | PASS | 200 |  |
| 84 | Gov-Meta | List meta roles | PASS | 200 |  |
| 85 | Gov-Meta | Create meta role | PASS | 200 | id=42fa9bf2-56af-40b4-8e02-d05dfc31475e |
| 86 | Gov-Meta | Get meta role | PASS | 200 |  |
| 87 | Gov-Meta | List conflicts | PASS | 200 |  |
| 88 | Gov-Meta | List events | PASS | 200 |  |
| 89 | Gov-Outlier | Get outlier config | PASS | 200 |  |
| 90 | Gov-Outlier | List analyses | PASS | 200 |  |
| 91 | Gov-Outlier | List results | PASS | 200 |  |
| 92 | Gov-Outlier | Get summary | PASS | 200 |  |
| 93 | Gov-Outlier | List alerts | PASS | 200 |  |
| 94 | Gov-NHI | List NHIs | PASS | 200 |  |
| 95 | Gov-NHI | Get NHI summary | PASS | 200 |  |
| 96 | Gov-Merge | List duplicates | PASS | 200 |  |
| 97 | Gov-Merge | List merge operations | PASS | 200 |  |
| 98 | Gov-Merge | List merge audits | PASS | 200 |  |
| 99 | Gov-Persona | List personas | PASS | 200 |  |
| 100 | Gov-Persona | Get current context | PASS | 200 |  |
| 101 | Gov-Persona | List context sessions | PASS | 200 |  |
| 102 | Gov-Persona | List persona audit | PASS | 200 |  |
| 103 | Gov-PoA | List PoA grants | PASS | 200 |  |
| 104 | Gov-PoA | Get current assumption | PASS | 200 |  |
| 105 | Gov-Esc | List escalation policies | PASS | 200 |  |
| 106 | Gov-Esc | List approval groups | PASS | 200 |  |
| 107 | Gov-Esc | List approval workflows | PASS | 200 |  |
| 108 | Gov-MicroCert | List micro-certifications | PASS | 200 |  |
| 109 | Gov-MicroCert | List micro-cert triggers | PASS | 200 |  |
| 110 | Gov-Orphan | List detection rules | PASS | 200 |  |
| 111 | Gov-Orphan | List orphan detections | PASS | 200 |  |
| 112 | Gov-Orphan | List service accounts | PASS | 200 |  |
| 113 | Gov-GDPR | Get GDPR report | PASS | 200 |  |
| 114 | Gov-GDPR | Get user data protection | PASS | 200 |  |
| 115 | Gov-SIEM | List SIEM destinations | PASS | 200 |  |
| 116 | Gov-SIEM | List SIEM batch exports | PASS | 200 |  |
| 117 | Gov-Tmpl | List object templates | PASS | 200 |  |
| 118 | Gov-License | List license pools | PASS | 200 |  |
| 119 | Gov-License | List license assignments | PASS | 200 |  |
| 120 | Gov-Script | List scripts | PASS | 200 |  |
| 121 | Gov-Script | List script templates | PASS | 200 |  |
| 122 | Gov-Corr | List correlation cases | PASS | 200 |  |
| 123 | Gov-Corr | List correlation audit | PASS | 200 |  |
| 124 | Gov-Corr | List identity correlation rules | PASS | 200 |  |
| 125 | Gov-Deleg | List delegations | PASS | 200 |  |
| 126 | Gov-Manual | List manual tasks | PASS | 200 |  |
| 127 | Connector | List connectors | PASS | 200 |  |
| 128 | NHI | List service accounts | PASS | 200 |  |
| 129 | NHI | Service account summary | PASS | 200 |  |
| 130 | NHI | List agents | PASS | 200 |  |
| 131 | NHI | List tools | PASS | 200 |  |
| 132 | NHI | List approvals | PASS | 200 |  |
| 133 | NHI | NHI risk summary | PASS | 200 |  |
| 134 | NHI | List NHI certification campaigns | PASS | 200 |  |
| 135 | Webhooks | List subscriptions | PASS | 200 |  |
| 136 | Webhooks | List event types | PASS | 200 |  |
| 137 | Webhooks | List DLQ entries | PASS | 200 |  |
| 138 | Webhooks | List circuit breakers | PASS | 200 |  |
| 139 | Audit | Login history | PASS | 200 |  |
| 140 | Audit | List security alerts | PASS | 200 |  |
| 141 | DelegAdmin | List permissions | PASS | 200 |  |
| 142 | DelegAdmin | List role templates | PASS | 200 |  |
| 143 | DelegAdmin | List assignments | PASS | 200 |  |
| 144 | DelegAdmin | Get audit log | PASS | 200 |  |
| 145 | Branding | Get branding config | PASS | 200 |  |
| 146 | Branding | List branding assets | PASS | 200 |  |
| 147 | Branding | List email templates | PASS | 200 |  |
| 148 | OAuthAdmin | List OAuth clients | PASS | 200 |  |
| 149 | OAuthAdmin | List active sessions | PASS | 200 |  |
| 150 | AuthZ | List policies | PASS | 200 |  |
| 151 | AuthZ | List mappings | PASS | 200 |  |
| 152 | AuthZ | Can-I check | PASS | 200 |  |
| 153 | KeyMgmt | List signing keys | PASS | 200 |  |
| 154 | Tenant | List API keys | PASS | 200 |  |
| 155 | Tenant | Get tenant settings | PASS | 200 |  |
| 156 | Tenant | List invitations | PASS | 200 |  |
| 157 | Tenant | List OAuth clients | PASS | 200 |  |
| 158 | System | Get tenant status | PASS | 200 |  |
| 159 | System | Get tenant usage | PASS | 200 |  |
| 160 | System | Get system settings | PASS | 200 |  |
| 161 | System | List plans | PASS | 200 |  |
| 162 | SAML | Get SAML metadata | PASS | 200 |  |
| 163 | SAML | List service providers | PASS | 200 |  |
| 164 | SAML | List certificates | PASS | 200 |  |
| 165 | Social | Available providers | PASS | 200 |  |
| 166 | Social | Admin list providers | PASS | 200 |  |
| 167 | Import | List import jobs | PASS | 200 |  |
| 168 | Invite | List invitations | PASS | 200 |  |
| 169 | Security | No auth (expect 401) | PASS | 401 | correctly rejected |
| 170 | Security | No tenant header (expect 4xx) | PASS | 401 | correctly rejected |
| 171 | Security | Invalid token (expect 401) | PASS | 401 | correctly rejected |
| 172 | Security | SQL injection attempt (not 500) | PASS | 000 | no server error |
| 173 | Cleanup | Revoke assignment | PASS | 204 |  |
| 174 | Cleanup | Delete SoD rule | PASS | 204 |  |
| 175 | Cleanup | Delete role-entitlement | PASS | 204 |  |
| 176 | Cleanup | Delete application | PASS | 204 |  |
| 177 | Cleanup | Cleanup complete | PASS | - |  |

## Summary
- **PASS**: 177
- **FAIL**: 0
- **SKIP**: 0
- **TOTAL**: 177
- **PASS RATE**: 100.0%
