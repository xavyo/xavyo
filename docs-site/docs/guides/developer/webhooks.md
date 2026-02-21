---
title: Webhooks
description: Receive real-time event notifications via webhooks — subscription management, signature verification, and DLQ.
sidebar_position: 4
---

# Webhooks

xavyo delivers real-time event notifications to your application via webhooks. When events occur (user created, login failed, role assigned, etc.), xavyo sends an HTTPS POST request to your registered endpoint with the event payload.

## Subscription Management

### Create a Subscription

```bash
curl -X POST https://idp.example.com/webhooks/subscriptions \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "User Events Webhook",
    "description": "Receive all user lifecycle events",
    "url": "https://app.example.com/webhooks/xavyo",
    "secret": "whsec_my-webhook-signing-secret",
    "event_types": ["user.created", "user.updated", "user.deleted"]
  }'
```

**Response (201 Created):**

```json
{
  "id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "User Events Webhook",
  "url": "https://app.example.com/webhooks/xavyo",
  "event_types": ["user.created", "user.updated", "user.deleted"],
  "enabled": true,
  "consecutive_failures": 0,
  "created_at": "2026-02-07T10:00:00Z",
  "updated_at": "2026-02-07T10:00:00Z"
}
```

### Update a Subscription

```bash
curl -X PATCH https://idp.example.com/webhooks/subscriptions/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "All Events Webhook",
    "event_types": ["user.created", "user.updated", "auth.login.success"],
    "enabled": true
  }'
```

### List Subscriptions

```bash
curl "https://idp.example.com/webhooks/subscriptions?limit=20&offset=0" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Delete a Subscription

```bash
curl -X DELETE https://idp.example.com/webhooks/subscriptions/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Event Types

xavyo supports 36 event types organized by category:

### User Lifecycle

| Event Type | Description |
|------------|-------------|
| `user.created` | A new user was created |
| `user.updated` | A user profile was updated |
| `user.deleted` | A user was deleted |
| `user.disabled` | A user account was disabled |
| `user.enabled` | A user account was enabled |

### Authentication

| Event Type | Description |
|------------|-------------|
| `auth.login.success` | A user logged in successfully |
| `auth.login.failed` | A login attempt failed |
| `auth.mfa.enrolled` | An MFA factor was enrolled |
| `auth.mfa.verified` | An MFA factor was verified |
| `auth.token.revoked` | A token was revoked |

### Group

| Event Type | Description |
|------------|-------------|
| `group.created` | A group was created |
| `group.deleted` | A group was deleted |
| `group.member.added` | A member was added to a group |
| `group.member.removed` | A member was removed from a group |

### Role and Entitlement

| Event Type | Description |
|------------|-------------|
| `role.assigned` | A role was assigned to a user |
| `role.unassigned` | A role was unassigned from a user |
| `entitlement.granted` | An entitlement was granted |
| `entitlement.revoked` | An entitlement was revoked |

### Governance

| Event Type | Description |
|------------|-------------|
| `access_request.created` | An access request was created |
| `access_request.approved` | An access request was approved |
| `access_request.denied` | An access request was denied |
| `certification.completed` | A certification campaign was completed |

### Provisioning

| Event Type | Description |
|------------|-------------|
| `provisioning.completed` | A provisioning task completed successfully |
| `provisioning.failed` | A provisioning task failed |
| `reconciliation.completed` | A reconciliation run completed |

### Admin

| Event Type | Description |
|------------|-------------|
| `tenant.settings.updated` | Tenant settings were updated |
| `connector.status.changed` | A connector status changed |
| `webhook.subscription.disabled` | A subscription was auto-disabled due to failures |

### Import and SCIM

| Event Type | Description |
|------------|-------------|
| `import.started` | A bulk user import started |
| `import.completed` | A bulk user import completed |
| `import.failed` | A bulk user import failed |
| `scim.sync.started` | A SCIM outbound sync started |
| `scim.sync.completed` | A SCIM outbound sync completed |
| `scim.sync.failed` | A SCIM outbound sync failed |
| `scim.operation.failed` | An individual SCIM operation failed |

### Agent Security

| Event Type | Description |
|------------|-------------|
| `agent.anomaly.detected` | An AI agent behavioral anomaly was detected |

## Payload Format

Every webhook delivery sends a JSON payload with this envelope structure:

```json
{
  "event_id": "e1f2g3h4-5678-90ab-cdef-1234567890ab",
  "event_type": "user.created",
  "timestamp": "2026-02-07T15:30:00Z",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "data": {
    "user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "email": "alice@example.com",
    "display_name": "Alice Smith"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | UUID | Unique identifier for this event (use for idempotency) |
| `event_type` | string | Event type (e.g., `user.created`) |
| `timestamp` | ISO 8601 | When the event occurred |
| `tenant_id` | UUID | Tenant that generated the event |
| `data` | object | Event-specific payload |

## Signature Verification

xavyo signs webhook payloads using HMAC-SHA256 with your shared secret. Always verify signatures to ensure payloads are authentic.

### Signature Headers

| Header | Description |
|--------|-------------|
| `X-Webhook-Signature` | HMAC-SHA256 hex digest |
| `X-Webhook-Timestamp` | Unix timestamp of signing |

The signature is computed over `{timestamp}.{body}` to prevent replay attacks.

### Verification Algorithm

1. Extract the `X-Webhook-Signature` and `X-Webhook-Timestamp` headers
2. Concatenate `timestamp + "." + raw_request_body`
3. Compute HMAC-SHA256 using your shared secret
4. Compare the computed signature with the header value using constant-time comparison
5. Optionally, reject requests where the timestamp is older than 5 minutes

### Node.js Example

```javascript
const crypto = require('crypto');

function verifyWebhookSignature(secret, timestamp, body, signature) {
  const payload = `${timestamp}.${body}`;
  const computed = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(computed, 'hex'),
    Buffer.from(signature, 'hex')
  );
}

// Express middleware
app.post('/webhooks/xavyo', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['x-webhook-signature'];
  const timestamp = req.headers['x-webhook-timestamp'];
  const body = req.body.toString();

  if (!verifyWebhookSignature(WEBHOOK_SECRET, timestamp, body, signature)) {
    return res.status(401).send('Invalid signature');
  }

  const event = JSON.parse(body);
  console.log(`Received ${event.event_type}: ${event.event_id}`);
  res.status(200).send('OK');
});
```

### Python Example

```python
import hmac
import hashlib

def verify_webhook_signature(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    payload = f"{timestamp}.".encode() + body
    computed = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)

# Flask example
@app.route('/webhooks/xavyo', methods=['POST'])
def handle_webhook():
    signature = request.headers.get('X-Webhook-Signature')
    timestamp = request.headers.get('X-Webhook-Timestamp')
    body = request.get_data()

    if not verify_webhook_signature(WEBHOOK_SECRET, timestamp, body, signature):
        return 'Invalid signature', 401

    event = request.get_json()
    print(f"Received {event['event_type']}: {event['event_id']}")
    return 'OK', 200
```

### Go Example

```go
func verifyWebhookSignature(secret, timestamp string, body []byte, signature string) bool {
    payload := []byte(timestamp + ".")
    payload = append(payload, body...)
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    computed := hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(computed), []byte(signature))
}
```

### Rust Example

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn verify_webhook_signature(secret: &str, timestamp: &str, body: &[u8], signature: &str) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let computed = hex::encode(mac.finalize().into_bytes());
    subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), signature.as_bytes()).into()
}
```

## Retry Policy

Failed deliveries are retried with exponential backoff:

| Attempt | Delay |
|---------|-------|
| 1 | Immediate |
| 2 | 1 minute |
| 3 | 5 minutes |
| 4 | 30 minutes |
| 5 | 2 hours |

After 5 failed attempts, the delivery is marked as `abandoned` and moved to the Dead Letter Queue.

:::tip
Return a `2xx` status code promptly (within 10 seconds) to acknowledge receipt. Process the event asynchronously if your handler takes longer. Any non-2xx response or timeout triggers a retry.
:::

## Circuit Breaker

xavyo automatically disables subscriptions that consistently fail to prevent wasted resources:

- After **10 consecutive failures**, the subscription is automatically disabled
- A `webhook.subscription.disabled` event is emitted
- Re-enable the subscription through the admin API after fixing the endpoint

### View Circuit Breaker Status

```bash
curl https://idp.example.com/webhooks/circuit-breakers \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Dead Letter Queue (DLQ)

Failed deliveries that exhaust all retry attempts are stored in the DLQ. You can browse, inspect, and replay them.

### List DLQ Entries

```bash
curl "https://idp.example.com/webhooks/dlq?limit=20&offset=0" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Get DLQ Entry Details

```bash
curl https://idp.example.com/webhooks/dlq/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The detail response includes the original payload, response codes, and error messages from each attempt.

### Replay a DLQ Entry

Re-attempt delivery of a failed event:

```bash
curl -X POST https://idp.example.com/webhooks/dlq/{id}/replay \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Delete a DLQ Entry

```bash
curl -X DELETE https://idp.example.com/webhooks/dlq/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Best Practices

1. **Always verify signatures** -- Never trust webhook payloads without verifying the HMAC-SHA256 signature
2. **Use the `event_id` for idempotency** -- Events may be delivered more than once due to retries. Use the `event_id` to deduplicate
3. **Respond quickly** -- Return `200 OK` within 10 seconds, then process asynchronously
4. **Use HTTPS endpoints** -- xavyo delivers webhooks only to HTTPS URLs in production
5. **Monitor the DLQ** -- Periodically check the Dead Letter Queue for failed deliveries
6. **Handle circuit breaker events** -- Subscribe to `webhook.subscription.disabled` to get alerted when a subscription is auto-disabled
7. **Validate timestamps** -- Reject events with timestamps older than 5 minutes to prevent replay attacks
