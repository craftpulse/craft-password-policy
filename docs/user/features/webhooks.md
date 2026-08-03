# Webhooks (Enterprise)

Enterprise installs can forward audit events to one or more HTTP webhook endpoints with HMAC-SHA-256 signing, replay-window protection, and idempotency UUIDs. Unlike [SIEM forwarders](./siem-forwarders.md) which are designed for log aggregation (at-least-once-to-one across endpoints), webhooks are designed for per-endpoint integration (every endpoint receives every row independently).

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

- **Adding a new endpoint** doesn't retroactively deliver the entire history: the cursor is set to the newest audit row at the moment you save the endpoint, so delivery starts from the next row written after that.
- **An endpoint that's down for a week** catches up the missed rows on recovery (subject to retention: rows pruned by GC are not redelivered).
- **Two endpoints with different filters** maintain independent watermarks: a Slack channel filtered to `hibp_breach_detected` and a SOC API filtered to all events deliver independently.

There is no backfill command. A new endpoint starts from the current row and there is no supported way to rewind its watermark, so if a receiver needs the historical events, use [Audit export](./audit-export.md) to hand them the window as a file instead. That is usually the better answer anyway: a backfill would hand the receiver a burst of thousands of events at once, and most receivers rate-limit long before they finish.

## Secret rotation

Rotate the signing secret using the **Rotate secret** action on the endpoint edit screen, or the console command:

```shell
./craft password-policy/webhook/rotate-secret 42
```

Either way:

1. The current secret moves to `secretPrevious` and a freshly generated secret becomes current.
2. The new plaintext is shown **once**, in a control panel flash message or on stdout. It is encrypted at rest and not recoverable afterwards, so capture it there or rotate again.
3. Through the grace window, the old secret remains stored so your receiver can still verify against it.
4. `RotateWebhookSecretJob` reaps the old secret once the window elapses.

The grace window exists for the receiver's benefit, not the plugin's. **The plugin signs with the new secret exclusively from the moment of rotation.** There is no header carrying a second signature, so a receiver that only knows the old secret starts failing verification immediately. Update your receiver during the window; the window buys you time to deploy, not dual-signing.

The window is set by `webhookSecretGracePeriodHours`, default **24 hours**, configurable up to 7 days. There is no per-rotation override.

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

Four commands, all Enterprise:

```shell
# Enqueue the delivery sweep; this is what makes deliveries happen
./craft password-policy/webhook/run
```

```shell
# Register an endpoint; prints the signing secret once
./craft password-policy/webhook/create \
    --url=https://hooks.example.com/audit \
    --name="Compliance dashboard" \
    --events=password_changed,hibp_breach_detected
```

```shell
# List endpoints with their id, enabled state, delivery cursor, and URL
./craft password-policy/webhook/list
```

```shell
# Rotate one endpoint's signing secret (id is positional)
./craft password-policy/webhook/rotate-secret 42
```

Test-firing and resetting a circuit are control panel actions, not commands. See [Console commands](../reference/console-commands.md#webhooks) for the full option reference.

> [!WARNING]
> **Delivery needs a cron entry and a queue runner**
>
> Two separate things have to be running, and an endpoint configured without both delivers nothing while reporting no error.
>
> `password-policy/webhook/run` is what puts `WebhookForwardJob` on the queue. Nothing else does: no request hook, no audit-write hook, no control panel action. Without that command on a schedule, no delivery is ever attempted and every endpoint's `lastDeliveredRowId` stays empty.
>
> A queue runner is what executes the job once it is queued. On a quiet site relying on Craft's default web-request-triggered runner, the pending count sits still even with the cron in place. Run the queue from cron too (`./craft queue/listen` under a process supervisor, or `./craft queue/run` on a schedule).
>
> See [Cron setup](../operations/cron-setup.md) for both entries.

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
