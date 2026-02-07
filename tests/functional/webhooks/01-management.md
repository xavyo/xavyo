# Webhook Management Functional Tests

**API Endpoints**:
- `POST /webhooks/subscriptions` (create webhook subscription)
- `GET /webhooks/subscriptions` (list subscriptions)
- `GET /webhooks/subscriptions/:id` (get subscription details)
- `PATCH /webhooks/subscriptions/:id` (update subscription)
- `DELETE /webhooks/subscriptions/:id` (delete subscription)
- `GET /webhooks/event-types` (list available event types)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: Webhook security (HMAC-SHA256 signing), OWASP API Security

---

## Nominal Cases

### TC-WEBHOOK-MGMT-001: Create webhook subscription
- **Category**: Nominal
- **Preconditions**: Authenticated admin
- **Input**:
  ```json
  POST /webhooks/subscriptions
  {
    "url": "https://hooks.example.com/xavyo",
    "events": ["user.created", "user.updated", "user.deleted"],
    "description": "User lifecycle events"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "url": "https://hooks.example.com/xavyo",
    "events": ["user.created", "user.updated", "user.deleted"],
    "secret": "<hmac_signing_secret>",
    "is_active": true,
    "created_at": "2026-02-07T..."
  }
  ```
- **Side Effects**: Signing secret generated (shown only on creation), audit log: `webhook.created`

### TC-WEBHOOK-MGMT-002: List webhook subscriptions
- **Category**: Nominal
- **Preconditions**: 3 subscriptions exist
- **Input**: `GET /webhooks/subscriptions`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "subscriptions": [
      { "id": "...", "url": "https://hooks.example.com/xavyo", "events": [...], "is_active": true, ... },
      { "id": "...", "url": "https://other.example.com/hook", "events": [...], "is_active": true, ... },
      { "id": "...", "url": "https://disabled.example.com", "events": [...], "is_active": false, ... }
    ]
  }
  ```
- **Verification**: Signing secrets are NOT included in list response

### TC-WEBHOOK-MGMT-003: Get subscription details
- **Category**: Nominal
- **Input**: `GET /webhooks/subscriptions/:id`
- **Expected Output**: Status 200, subscription details without secret

### TC-WEBHOOK-MGMT-004: Update webhook subscription
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /webhooks/subscriptions/:id
  {
    "events": ["user.created", "user.deleted", "group.updated"],
    "description": "Updated events"
  }
  ```
- **Expected Output**: Status 200, subscription updated
- **Side Effects**: Audit log: `webhook.updated`

### TC-WEBHOOK-MGMT-005: Delete webhook subscription
- **Category**: Nominal
- **Input**: `DELETE /webhooks/subscriptions/:id`
- **Expected Output**: Status 200, subscription deleted
- **Side Effects**: No further events delivered, audit log: `webhook.deleted`

### TC-WEBHOOK-MGMT-006: List available event types
- **Category**: Nominal
- **Input**: `GET /webhooks/event-types`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "event_types": [
      { "name": "user.created", "description": "Fired when a new user is created" },
      { "name": "user.updated", "description": "Fired when a user is updated" },
      { "name": "user.deleted", "description": "Fired when a user is deleted" },
      { "name": "group.created", "description": "..." },
      { "name": "session.created", "description": "..." },
      ...
    ]
  }
  ```

### TC-WEBHOOK-MGMT-007: Create subscription for all events
- **Category**: Nominal
- **Input**:
  ```json
  POST /webhooks/subscriptions
  { "url": "https://hooks.example.com/all", "events": ["*"] }
  ```
- **Expected Output**: Status 201, subscription receives all event types

### TC-WEBHOOK-MGMT-008: Update subscription URL
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /webhooks/subscriptions/:id
  { "url": "https://new-endpoint.example.com/hook" }
  ```
- **Expected Output**: Status 200, URL updated

### TC-WEBHOOK-MGMT-009: Deactivate webhook (keep but stop delivery)
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /webhooks/subscriptions/:id
  { "is_active": false }
  ```
- **Expected Output**: Status 200, subscription marked inactive, no events delivered

### TC-WEBHOOK-MGMT-010: Reactivate webhook
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /webhooks/subscriptions/:id
  { "is_active": true }
  ```
- **Expected Output**: Status 200, events resume delivery

---

## Edge Cases

### TC-WEBHOOK-MGMT-011: Create subscription with invalid URL
- **Category**: Edge Case
- **Input**: `{ "url": "not-a-url", "events": ["user.created"] }`
- **Expected Output**: Status 400 "Invalid URL"

### TC-WEBHOOK-MGMT-012: Create subscription with HTTP URL (not HTTPS)
- **Category**: Edge Case
- **Input**: `{ "url": "http://hooks.example.com/insecure", "events": ["user.created"] }`
- **Expected Output**: Status 400 "URL must use HTTPS" OR Status 201 (if allowed for dev/testing)

### TC-WEBHOOK-MGMT-013: Create subscription with no events
- **Category**: Edge Case
- **Input**: `{ "url": "https://hooks.example.com", "events": [] }`
- **Expected Output**: Status 400 "At least one event type required"

### TC-WEBHOOK-MGMT-014: Create subscription with invalid event type
- **Category**: Edge Case
- **Input**: `{ "url": "https://hooks.example.com", "events": ["nonexistent.event"] }`
- **Expected Output**: Status 400 "Invalid event type: nonexistent.event"

### TC-WEBHOOK-MGMT-015: Delete non-existent subscription
- **Category**: Edge Case
- **Input**: `DELETE /webhooks/subscriptions/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404

### TC-WEBHOOK-MGMT-016: Update non-existent subscription
- **Category**: Edge Case
- **Input**: `PATCH /webhooks/subscriptions/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404

### TC-WEBHOOK-MGMT-017: Create subscription with localhost URL
- **Category**: Edge Case / Security
- **Input**: `{ "url": "https://localhost:8080/hook", "events": ["user.created"] }`
- **Expected Output**: Status 400 "Private/localhost URLs not allowed" (SSRF prevention)

### TC-WEBHOOK-MGMT-018: Create subscription with private IP URL
- **Category**: Edge Case / Security
- **Input**: `{ "url": "https://10.0.0.1/hook", "events": ["user.created"] }`
- **Expected Output**: Status 400 "Private IP URLs not allowed" (SSRF prevention)

### TC-WEBHOOK-MGMT-019: Maximum subscriptions per tenant
- **Category**: Edge Case
- **Preconditions**: Tenant has reached max subscription limit (e.g., 50)
- **Input**: Create one more subscription
- **Expected Output**: Status 400 "Maximum webhook subscriptions reached"

---

## Security Cases

### TC-WEBHOOK-MGMT-020: Signing secret generated with sufficient entropy
- **Category**: Security
- **Verification**: Secret is at least 32 bytes, generated via CSPRNG

### TC-WEBHOOK-MGMT-021: Signing secret shown only on creation
- **Category**: Security
- **Verification**: `GET /webhooks/subscriptions/:id` does NOT return the secret
- `GET /webhooks/subscriptions` does NOT return secrets

### TC-WEBHOOK-MGMT-022: Non-admin cannot manage webhooks
- **Category**: Security
- **Input**: Regular user calls `POST /webhooks/subscriptions`
- **Expected Output**: Status 403 Forbidden

### TC-WEBHOOK-MGMT-023: Cross-tenant webhook isolation
- **Category**: Security
- **Preconditions**: Tenant A has subscription S1
- **Input**: Admin of tenant B calls `GET /webhooks/subscriptions/:s1_id`
- **Expected Output**: Status 404

### TC-WEBHOOK-MGMT-024: SSRF prevention on webhook URL
- **Category**: Security
- **Standard**: OWASP ASVS 5.2.6
- **Verification**: URLs pointing to internal services (169.254.x.x, 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16-31.x.x) are rejected

### TC-WEBHOOK-MGMT-025: Audit trail for webhook management
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Verification**: Audit logs for: creation, update, deletion, activation, deactivation
