# Webhooks (Enterprise)

Enterprise installs can forward audit events to one or more HTTP webhook endpoints with HMAC-SHA-256 signing, replay-window protection, and idempotency UUIDs. Unlike [SIEM forwarders](./siem-forwarders.md) which are designed for log aggregation (at-least-once-to-one across endpoints), webhooks are designed for per-endpoint integration (every endpoint receives every row independently).

> 📷 *Screenshot: Webhooks index page showing three configured endpoints, "Slack #security alerts" (green-status, 12 successful deliveries today), "Internal SOC API" (green-status, 47 deliveries today), "Vendor compliance webhook" (amber-status, 2 retries in flight). Each row shows endpoint URL, last delivery, signature scheme.*

This page covers configuring webhook endpoints, the signature scheme, replay-window verification, secret rotation with grace windows, and the per-endpoint delivery watermark model.

## Quick start

1. Open **Password Policy → Webhooks → New endpoint** in the control panel.
2. Configure the destination URL.
3. Generate a signing secret (or paste an existing one).
4. Save. The plugin starts delivering every new audit row to your endpoint signed with your secret.

## Configuration

### Webhook endpoint fields

| Setting | Required | Example |
|---|---|---|
| Name | Yes | "Slack #security alerts" |
| Endpoint URL | Yes | `https://hooks.example.com/audit-events` |
| Signing secret | Yes (generated on create) | 64 hex chars |
| Event filter | No (defaults to all) | `password_changed,hibp_breach_detected,policy_changed` |
| Enabled | Yes (default on) | toggle |

The endpoint URL must be HTTPS: the plugin's Guzzle client enforces TLS verification at the request site (overrides any site-level `config/guzzle.php` `verify => false`).

The signing secret is stored encrypted in `passwordpolicy_webhook_endpoints` and never displayed in plain text after creation. Use the **Rotate secret** action if you suspect it's been compromised.

### Event filtering

By default, every audit event fires for every webhook endpoint. Configure a comma-separated list of event names in the **Event filter** field to scope an endpoint to specific events:

```
password_changed, hibp_breach_detected, policy_changed
```

Only events matching the filter trigger a delivery. The filter is exact-match per event name, see [Audit logging → What's captured](./audit-logging.md#whats-captured) for the canonical event list.

## HMAC-SHA-256 signing

Every delivery carries an HMAC-SHA-256 signature of the request body + timestamp + idempotency UUID, signed with your endpoint's secret.

### Request headers

```http
POST /audit-events HTTP/1.1
Host: hooks.example.com
Content-Type: application/json
X-PasswordPolicy-Signature: sha256=8e3a4f2d2c1b9e76a4f3a3b2c1d0e9f8...
X-PasswordPolicy-Timestamp: 2026-05-15T03:33:14Z
X-PasswordPolicy-Event-Id: 6f7e8d9c-1234-5678-9abc-def012345678
X-PasswordPolicy-Plugin-Version: 5.2.0
```

| Header | Purpose |
|---|---|
| `X-PasswordPolicy-Signature` | HMAC-SHA-256 of the signing envelope. Format: `sha256=<hex>` |
| `X-PasswordPolicy-Timestamp` | UTC ISO 8601 timestamp of the delivery attempt. Used for replay-window verification. |
| `X-PasswordPolicy-Event-Id` | UUID v4 unique to this delivery. Receivers should dedup on this, see [Idempotency](#idempotency). |
| `X-PasswordPolicy-Plugin-Version` | The plugin version that produced the delivery. Diagnostics + version-skew handling. |

### Signing envelope

The HMAC signs a concatenation of three values separated by `.`:

```
{timestamp}.{eventId}.{body}
```

Where:

- `timestamp` is the literal value of `X-PasswordPolicy-Timestamp`.
- `eventId` is the literal value of `X-PasswordPolicy-Event-Id`.
- `body` is the raw bytes of the HTTP request body.

This three-part envelope prevents:

- **Body tampering**: modifying any byte invalidates the signature.
- **Timestamp tampering**: replaying with a different timestamp invalidates the signature (and the receiver can reject stale timestamps independently).
- **Cross-event replay**: signing the eventId binds the signature to a specific delivery; it can't be reused for a different event.

### Receiver verification

The canonical verification procedure on the receiving side:

```python
import hmac, hashlib

def verify(headers, body, secret):
    signature = headers['X-PasswordPolicy-Signature']
    timestamp = headers['X-PasswordPolicy-Timestamp']
    event_id = headers['X-PasswordPolicy-Event-Id']

    if not signature.startswith('sha256='):
        return False

    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{event_id}.{body.decode()}".encode(),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature[7:], expected)
```

`hmac.compare_digest` is essential, string equality (`==`) is timing-sensitive and would leak the signature one byte at a time to a sophisticated attacker.

### Replay-window verification

In addition to signature verification, receivers should reject requests with a timestamp more than 5 minutes from "now":

```python
from datetime import datetime, timezone, timedelta

def within_replay_window(headers, window_seconds=300):
    ts = datetime.fromisoformat(headers['X-PasswordPolicy-Timestamp'].replace('Z', '+00:00'))
    now = datetime.now(timezone.utc)
    return abs((now - ts).total_seconds()) <= window_seconds
```

This prevents an attacker who captured a valid past delivery from replaying it months later. Combined with the eventId-based idempotency, the replay window provides defense-in-depth against replay attacks.

### Idempotency

Every delivery carries a UUID v4 in `X-PasswordPolicy-Event-Id`. Two retries of the same delivery (e.g. the receiver returned 502 the first time, succeeded the second time) carry the **same** eventId. Receivers should dedup on this UUID to prevent processing the same event twice:

```python
def handle_webhook(headers, body, secret):
    if not verify(headers, body, secret):
        return 401
    if not within_replay_window(headers):
        return 401

    event_id = headers['X-PasswordPolicy-Event-Id']
    if cache.exists(f"webhook-seen:{event_id}"):
        return 200  # already processed; ack but skip
    cache.set(f"webhook-seen:{event_id}", 1, ttl=86400)

    process(body)
    return 200
```

The plugin retries failed deliveries up to 5 times with exponential backoff. After 5 failures, the endpoint's circuit opens (see [Circuit breaker](#circuit-breaker) below). All retries within a batch carry the same eventId, so receiver-side dedup works as expected.

## Body shape

The request body is the canonical JSON of the audit row plus a `_meta` envelope:

```json
{
    "event": "password_changed",
    "userIdentifier": "a3f4b...",
    "userId": 42,
    "ipHash": "c91d7...",
    "outcome": "success",
    "details": {
        "source": "front-end-change",
        "method": "self",
        "reason": "user_change"
    },
    "previousHash": "...",
    "rowHash": "...",
    "dateCreated": "2026-05-15T03:33:14Z",
    "_meta": {
        "rowId": 8821,
        "endpointId": 3,
        "hostname": "craft-prod",
        "pluginVersion": "5.2.0"
    }
}
```

The `_meta` envelope is **not** part of the signed body for hash-chain purposes, it's added at delivery time for receiver convenience. The signed envelope is the entire request body (including `_meta`), so signature verification still covers the metadata.

## Per-endpoint watermark

Unlike SIEM forwarders (at-least-once-to-one across endpoints), webhooks use a per-endpoint watermark. Each endpoint's `lastDeliveredRowId` column tracks the last successfully-delivered audit row.

This means:

- **Adding a new endpoint** doesn't retroactively deliver the entire history: it starts from the current row.
- **An endpoint that's down for a week** catches up the missed rows on recovery (subject to retention: rows pruned by GC are not redelivered).
- **Two endpoints with different filters** maintain independent watermarks: a Slack channel filtered to `hibp_breach_detected` and a SOC API filtered to all events deliver independently.

To **backfill** an endpoint with historical events (e.g. you just added a new compliance webhook and want it to receive everything from the past 90 days), use the bundled command:

```bash
./craft password-policy/webhook/backfill --endpoint=<id> --from=2026-02-15
```

The command resets `lastDeliveredRowId` and queues the backlog for delivery. Use with care: the receiver gets a burst of N events all at once.

## Secret rotation

Rotate the signing secret without breaking in-flight signatures using the **Rotate secret** action on the endpoint edit screen:

> 📷 *Screenshot: Webhook endpoint edit screen with the "Rotate secret" button visible at the bottom of the configuration panel; below it, a "Previous secret retained until 2026-05-15 03:38:14 (grace window)" callout.*

1. Click **Rotate secret**.
2. The plugin generates a new secret + saves it.
3. Both the **new** and **old** secrets are valid for a 5-minute grace window: every delivery in that window is signed with the new secret but the old secret's HMAC is also published in a `X-PasswordPolicy-Signature-Previous` header so receivers can verify either.
4. After 5 minutes, the `RotateWebhookSecretJob` reaper job runs and clears the old secret.
5. Update your receiver-side stored secret during the grace window.

The grace window prevents the standard "rotation race": a request signed with the old secret arrives at the receiver after they've already updated to the new one (or vice versa). The dual-secret window covers both directions.

If 5 minutes isn't enough (slow infrastructure rollout), schedule the rotation outside business hours or use the longer-window variant:

```bash
./craft password-policy/webhook/rotate --endpoint=<id> --grace=3600
```

Defaults to 300 seconds; configurable up to 86,400 (24 hours).

## Circuit breaker

Each endpoint has a per-endpoint circuit breaker matching the [SIEM forwarder pattern](./siem-forwarders.md#circuit-breaker):

- **Closed state**: every delivery attempt runs.
- **Open state**: after 5 consecutive failures, the breaker opens. Subsequent runs skip the endpoint.
- **Half-open**: after 5 minutes in the open state, the next run attempts a single delivery.

Circuit state is stored durably in the `passwordpolicy_webhook_endpoints` table. A cache flush doesn't reset it.

The dashboard's **Pending forwards** section shows broken-circuit endpoints alongside SIEM forwarders.

## CP management

### Endpoints index

**Password Policy → Webhooks** lists every endpoint with status pill, last-delivery time, and quick actions:

- **Edit**: configuration screen
- **Test fire**: sends a synthetic event to the endpoint and surfaces the response
- **Rotate secret**: generates a new secret with the 5-minute grace window
- **Reset circuit**: manually closes a broken circuit after fixing the underlying issue
- **Delete**: removes the endpoint (audit history retained)

### Endpoint edit screen

Three tabs:

- **Configuration**: URL, event filter, enabled toggle
- **Authentication**: signing secret (read-only after creation), rotate-secret action
- **Activity**: last 50 deliveries with status code, response body excerpt, timing

The **Activity** tab is useful for debugging: every delivery is captured with the receiver's response.

## Console commands

```bash
# Trigger an immediate delivery run
./craft password-policy/webhook/run

# Test-fire a specific endpoint
./craft password-policy/webhook/test --endpoint=<id>

# Rotate the signing secret with custom grace window
./craft password-policy/webhook/rotate --endpoint=<id> --grace=300

# Reset a broken circuit
./craft password-policy/webhook/reset-circuit --endpoint=<id>

# Backfill historical events to a new endpoint
./craft password-policy/webhook/backfill --endpoint=<id> --from=2026-02-15
```

## Permissions

| Permission | What it grants |
|---|---|
| `pp:webhooks-manage` | Full CRUD on endpoints + test-fire + rotate-secret + reset-circuit + backfill. Enterprise-only. |

## Use cases

- **Slack channel for security alerts**: endpoint filtered to `hibp_breach_detected, account_locked, policy_changed`. POST to Slack's webhook URL. The Slack-side receiver formats the JSON into a readable message.
- **SOC integration**: internal SOC API receives every event; the receiver classifies events as critical/medium/low and routes to the right on-call channel.
- **Compliance vendor**: third-party compliance platform (Drata, Vanta, etc.) receives `password_changed`, `policy_changed`, `account_locked` events for evidence collection.
- **Audit retention archive**: long-term storage of every event in S3 via an API Gateway → Lambda → S3 pipeline. Combine with retention purge on the plugin side: the warehouse keeps the long history; the plugin keeps the operational window.

## See also

- [Audit logging](./audit-logging.md): the source of audit events that get delivered.
- [SIEM forwarders](./siem-forwarders.md): alternative at-least-once-to-one delivery for log aggregation.
- [Audit export](./audit-export.md): batch export to filesystem for offline analysis.
- [Compliance Dashboard](./compliance-dashboard.md): pending-deliveries surface for operators.
- [Events](../reference/events.md): `EVENT_WEBHOOK_DELIVERY_ATTEMPT` fires on every delivery attempt for custom monitoring integrations.
