# Webhook Delivery Functional Tests

**API Endpoints**:
- `GET /webhooks/subscriptions/:id/deliveries` (list delivery history)
- `GET /webhooks/subscriptions/:id/deliveries/:delivery_id` (get delivery detail)
- `GET /webhooks/dlq` (list dead letter queue entries)
- `GET /webhooks/dlq/:id` (get DLQ entry details)
- `DELETE /webhooks/dlq/:id` (delete DLQ entry)
- `POST /webhooks/dlq/:id/replay` (replay single DLQ entry)
- `POST /webhooks/dlq/replay` (bulk replay DLQ entries)
- `GET /webhooks/circuit-breakers` (list circuit breaker states)
- `GET /webhooks/circuit-breakers/:subscription_id` (get circuit breaker for subscription)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: Reliability patterns (circuit breaker, DLQ), webhook HMAC signing

---

## Nominal Cases

### TC-WEBHOOK-DLV-001: Event triggers webhook delivery
- **Category**: Nominal
- **Preconditions**: Subscription exists for `user.created` events, target endpoint is reachable
- **Steps**:
  1. Create a user (triggers `user.created` event)
  2. Check delivery history
- **Expected Output**: Delivery record created:
  ```
  {
    "id": "<uuid>",
    "subscription_id": "<uuid>",
    "event_type": "user.created",
    "status": "delivered",
    "status_code": 200,
    "attempted_at": "2026-02-07T...",
    "response_time_ms": 150
  }
  ```
- **Verification**: Target endpoint received POST with:
  - `Content-Type: application/json`
  - `X-Webhook-Signature: sha256=<hmac>` header
  - JSON body with event data

### TC-WEBHOOK-DLV-002: Webhook payload HMAC signature
- **Category**: Nominal
- **Standard**: Webhook security best practices
- **Verification**: Delivery includes `X-Webhook-Signature` header computed as:
  ```
  HMAC-SHA256(signing_secret, request_body)
  ```
  - Recipient can verify: `computed_sig == header_sig`

### TC-WEBHOOK-DLV-003: List delivery history
- **Category**: Nominal
- **Preconditions**: Subscription has 10 past deliveries
- **Input**: `GET /webhooks/subscriptions/:id/deliveries`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "deliveries": [
      { "id": "...", "event_type": "user.created", "status": "delivered", "status_code": 200, ... },
      { "id": "...", "event_type": "user.updated", "status": "failed", "status_code": 500, ... },
      ...
    ]
  }
  ```

### TC-WEBHOOK-DLV-004: Get delivery details
- **Category**: Nominal
- **Input**: `GET /webhooks/subscriptions/:id/deliveries/:delivery_id`
- **Expected Output**: Status 200, full delivery details including request headers, response status, timing

### TC-WEBHOOK-DLV-005: Failed delivery triggers retry
- **Category**: Nominal
- **Standard**: Reliability pattern (exponential backoff)
- **Preconditions**: Target endpoint returns 500
- **Steps**: Trigger event, observe retries
- **Expected Output**: System retries with exponential backoff (e.g., 1s, 2s, 4s, 8s, ...)
- **Verification**: Multiple delivery attempt records created

### TC-WEBHOOK-DLV-006: DLQ entry created after max retries
- **Category**: Nominal
- **Preconditions**: Target endpoint consistently fails, max retries exhausted
- **Steps**: Check DLQ after all retries fail
- **Input**: `GET /webhooks/dlq`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "entries": [
      {
        "id": "<uuid>",
        "subscription_id": "<uuid>",
        "event_type": "user.created",
        "payload": { ... },
        "last_error": "HTTP 500",
        "retry_count": 5,
        "created_at": "2026-02-07T..."
      }
    ]
  }
  ```

### TC-WEBHOOK-DLV-007: Replay single DLQ entry
- **Category**: Nominal
- **Preconditions**: DLQ entry exists, target endpoint is now healthy
- **Input**: `POST /webhooks/dlq/:id/replay`
- **Expected Output**: Status 200, delivery retried
- **Side Effects**: If successful, DLQ entry removed

### TC-WEBHOOK-DLV-008: Bulk replay DLQ entries
- **Category**: Nominal
- **Input**:
  ```json
  POST /webhooks/dlq/replay
  { "entry_ids": ["<uuid1>", "<uuid2>", "<uuid3>"] }
  ```
- **Expected Output**: Status 200, all entries reprocessed

### TC-WEBHOOK-DLV-009: Circuit breaker opens after repeated failures
- **Category**: Nominal
- **Standard**: Circuit breaker pattern
- **Preconditions**: Target endpoint fails 5 consecutive times
- **Steps**: Check circuit breaker state
- **Input**: `GET /webhooks/circuit-breakers/:subscription_id`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "subscription_id": "<uuid>",
    "state": "open",
    "failure_count": 5,
    "opened_at": "2026-02-07T...",
    "half_open_at": "2026-02-07T10:05:00Z"
  }
  ```
- **Verification**: While open, no deliveries are attempted (events queued or dropped)

### TC-WEBHOOK-DLV-010: Circuit breaker transitions to half-open
- **Category**: Nominal
- **Preconditions**: Circuit breaker is open, cooldown period elapsed
- **Verification**: Next event triggers a probe delivery; if successful, breaker closes

---

## Edge Cases

### TC-WEBHOOK-DLV-011: Delivery to endpoint that returns 3xx redirect
- **Category**: Edge Case
- **Preconditions**: Target returns 301/302
- **Expected Output**: Delivery follows redirect (up to limit) OR marks as failed

### TC-WEBHOOK-DLV-012: Delivery timeout (slow endpoint)
- **Category**: Edge Case
- **Preconditions**: Target endpoint takes 30+ seconds to respond
- **Expected Output**: Delivery times out (e.g., 10s), marked as failed, retry scheduled

### TC-WEBHOOK-DLV-013: List deliveries for subscription with no history
- **Category**: Edge Case
- **Input**: `GET /webhooks/subscriptions/:new_sub_id/deliveries`
- **Expected Output**: Status 200, empty array

### TC-WEBHOOK-DLV-014: Delete DLQ entry
- **Category**: Edge Case
- **Input**: `DELETE /webhooks/dlq/:id`
- **Expected Output**: Status 200, entry permanently removed (event lost)

### TC-WEBHOOK-DLV-015: Replay DLQ entry that no longer exists
- **Category**: Edge Case
- **Input**: `POST /webhooks/dlq/00000000-0000-0000-0000-000000000099/replay`
- **Expected Output**: Status 404

### TC-WEBHOOK-DLV-016: Inactive subscription does not receive deliveries
- **Category**: Edge Case
- **Preconditions**: Subscription is inactive
- **Steps**: Trigger matching event
- **Expected Output**: No delivery attempted, no DLQ entry created

---

## Security Cases

### TC-WEBHOOK-DLV-017: Webhook payload does not contain sensitive data
- **Category**: Security
- **Standard**: OWASP ASVS 8.3.4
- **Verification**: Webhook payloads do NOT contain:
  - Password hashes
  - API key values
  - JWT tokens
  - Any credentials

### TC-WEBHOOK-DLV-018: Cross-tenant delivery isolation
- **Category**: Security
- **Verification**: Events from tenant A are NEVER delivered to tenant B's webhook subscriptions

### TC-WEBHOOK-DLV-019: DLQ does not expose other tenants' data
- **Category**: Security
- **Input**: `GET /webhooks/dlq` as tenant A admin
- **Expected Output**: Only tenant A's DLQ entries visible

### TC-WEBHOOK-DLV-020: Delivery attempt limits prevent resource exhaustion
- **Category**: Security
- **Verification**: Maximum retry count is bounded (e.g., 5 retries), preventing infinite retry loops
