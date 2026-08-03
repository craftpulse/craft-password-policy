# Webhooks (Enterprise)

Enterprise installs can POST audit rows to one or more HTTPS endpoints, HMAC-SHA-256 signed, with a delivery timestamp for replay-window checks and a stable event id for idempotency. Unlike [SIEM forwarders](./siem-forwarders.md), which are designed for log aggregation (at-least-once-to-one across endpoints), webhooks are designed for per-endpoint integration: every endpoint receives every row independently.

This page covers configuring webhook endpoints, the signature scheme, replay-window verification, secret rotation with grace windows, and the per-endpoint delivery watermark model.

## Quick start

1. Open **Password Policy → Webhooks → New endpoint** in the control panel.
2. Enter the destination URL. It has to be HTTPS.
3. Save. The plugin generates a signing secret and shows it exactly once, in a panel on the endpoint's edit screen. Capture it there: it is stored encrypted and cannot be read back. If you miss it, **Rotate secret** issues a new one.
4. Put `password-policy/webhook/run` on a cron schedule and make sure a queue runner is running. Nothing is delivered until both are in place, see [Console commands](#console-commands) below.

## Configuration

### Webhook endpoint fields

| Field | Required | Notes |
|---|---|---|
| Name | No | Display label, for example "Compliance dashboard". The index falls back to the URL when it's empty. |
| URL | Yes | `https://hooks.example.com/audit-events`. Accepts an environment variable reference such as `$PP_WEBHOOK_URL`. |
| Enabled | Yes | On by default. Disabled endpoints are skipped by the queue job entirely. |
| Event class allowlist | No | Empty means "use the global setting". See [Event eligibility](#event-eligibility). |

The signing secret is generated for you on create. There is no field for it.

The endpoint URL must be HTTPS. The model rejects a literal `http://` URL, and because an environment variable reference skips that check, the resolved value is re-checked at dispatch time and a non-HTTPS target is refused rather than sent. TLS verification is enforced at the request site, which overrides any site-level `config/guzzle.php` `verify => false`.

The secret is stored encrypted in `passwordpolicy_webhook_endpoints` and never displayed in plain text after the one render that follows creation. Use the **Rotate secret** action if you suspect it's been compromised.

### Event eligibility

An endpoint only receives audit rows when its eligible event classes include the `audit_log` stream. Two layers decide that:

- **`webhookForwardEventClasses`**, a plugin setting, is the global default. It ships as `['audit_log']` and there is no control panel field for it. Set it in `config/password-policy.php` if you need to change it.
- The **Event class allowlist** field on each endpoint overrides the global setting for that row when it's non-empty.

`audit_log` is the only supported stream in 5.2.0. The field exists because the shape is forward-compatible with future streams, not because there is a second value to pick today.

There is no per-event-name filtering. An endpoint receives every audit row, and a receiver that only cares about some events discriminates on the body's `event` key. See [Audit logging → What's captured](./audit-logging.md#whats-captured) for the canonical event list.

> [!WARNING]
> **An allowlist that doesn't name `audit_log` delivers nothing, silently**
>
> An endpoint whose eligible classes exclude `audit_log` is never dispatched to. It is not a failure, so the circuit stays closed, the status pill stays green, and no warning appears anywhere. The cursor simply never moves.
>
> Leave the field empty unless you have a reason not to. If you fill it in, `audit_log` has to be in the list.

## HMAC-SHA-256 signing

Every delivery carries an HMAC-SHA-256 signature over the timestamp, the event id and the request body, signed with your endpoint's secret.

### Request headers

```http
POST /audit-events HTTP/1.1
Host: hooks.example.com
Content-Type: application/json
X-PasswordPolicy-Signature: sha256=8e3a4f2d2c1b9e76a4f3a3b2c1d0e9f8...
X-PasswordPolicy-Timestamp: 1778830394
X-PasswordPolicy-Event-Id: 6f7e8d9c-1234-5678-9abc-def012345678
```

| Header | Purpose |
|---|---|
| `X-PasswordPolicy-Signature` | HMAC-SHA-256 of the signing envelope. Format: `sha256=<hex>` |
| `X-PasswordPolicy-Timestamp` | **Unix epoch seconds** at the moment of the delivery attempt, as a decimal string. Used for replay-window verification. |
| `X-PasswordPolicy-Event-Id` | The audit row's own UUID. Stable across every delivery attempt for that row, which is what makes receiver-side dedup work. See [Idempotency](#idempotency). |

Those three are the only headers the plugin adds, alongside `Content-Type: application/json`. There is no plugin-version header.

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
- **Cross-event replay**: signing the eventId binds the signature to one specific audit row; it can't be reused for a different one.

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

In addition to signature verification, receivers should reject requests with a timestamp more than 5 minutes from "now". The header is Unix epoch seconds, so parse it as an integer:

```python
import time

def within_replay_window(headers, window_seconds=300):
    ts = int(headers['X-PasswordPolicy-Timestamp'])
    return abs(time.time() - ts) <= window_seconds
```

This prevents an attacker who captured a valid past delivery from replaying it months later. Combined with the eventId-based idempotency, the replay window provides defense-in-depth against replay attacks.

### Idempotency

`X-PasswordPolicy-Event-Id` carries the audit row's own UUID, not a per-attempt identifier. Two attempts at the same row (the receiver returned 502 on the first sweep and 200 on the next) carry the **same** eventId. Receivers should dedup on it to prevent processing the same event twice:

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

There is no in-request retry and no backoff schedule. A failed delivery ends that endpoint's pass for the current sweep and leaves its cursor where it was, so the next sweep retries the same row from the same place. Consecutive failures accumulate on the endpoint and open its circuit at the configured threshold, see [Circuit breaker](#circuit-breaker) below. Because the eventId is the row's UUID, every retry of a row carries the same value and receiver-side dedup works as expected.

## Body shape

The request body is the audit-log row as canonical JSON, and nothing else. There is no envelope and no added metadata. Keys are sorted recursively as strings, with unescaped slashes and unescaped unicode:

```json
{
    "changedByIdentifier": null,
    "changedByUserId": null,
    "dateCreated": "2026-05-15 03:33:14",
    "details": "{\"method\":\"self\",\"reason\":\"user_change\",\"source\":\"front-end-change\"}",
    "event": "password_changed",
    "forwardAttempts": 0,
    "forwardedAt": null,
    "geoCountry": null,
    "geoRegion": null,
    "id": 8821,
    "ipHash": "c91d7...",
    "outcome": "success",
    "previousHash": "...",
    "rowHash": "...",
    "source": "web",
    "uid": "6f7e8d9c-1234-5678-9abc-def012345678",
    "userId": 42,
    "userIdentifier": "a3f4b..."
}
```

Three things to know before writing a parser against it:

- **`details` arrives as a JSON string, not a nested object.** The column value is passed through verbatim, so it reads as `"{\"source\":\"admin\"}"`. Field extraction that expects nested keys needs a decode step first.
- **`dateCreated` is the raw column value**, `YYYY-MM-DD HH:MM:SS` in UTC, not ISO 8601. The delivery timestamp in the `X-PasswordPolicy-Timestamp` header is a separate value and a different format.
- **`forwardedAt` and `forwardAttempts` describe SIEM forwarder progress**, not webhook delivery. They are whatever the [SIEM forwarder](./siem-forwarders.md) left on the row, and the row id you need for correlation is `id`.

The signature covers exactly these bytes. Verify against the raw body you received, not a re-serialisation of it.

Recomputing `rowHash` from this body will not reproduce the stored value: the hash chain covers a narrower nine-key payload with `details` as a decoded object. For chain verification, run the [audit verifier](./audit-verifier.md) against the source install.

[SIEM forwarders](./siem-forwarders.md) put the same canonical JSON in the syslog message, so a receiver written against one shape parses the other.

## Per-endpoint watermark

Unlike SIEM forwarders (at-least-once-to-one across endpoints), webhooks use a per-endpoint watermark. Each endpoint's `lastDeliveredRowId` column tracks the last successfully-delivered audit row.

This means:

- **Adding a new endpoint** doesn't retroactively deliver the entire history: the cursor is set to the newest audit row at the moment you save the endpoint, so delivery starts from the next row written after that.
- **An endpoint that's down for a week** catches up the missed rows on recovery (subject to retention: rows pruned by GC are not redelivered).
- **Two endpoints move independently.** A slow or broken receiver holds up its own cursor only. The other endpoints keep delivering from theirs.

There is no backfill command. A new endpoint starts from the current row and there is no supported way to rewind its watermark, so if a receiver needs the historical events, use [Audit export](./audit-export.md) to hand them the window as a file instead. That is usually the better answer anyway: a backfill would hand the receiver a burst of thousands of events at once, and most receivers rate-limit long before they finish.

## Secret rotation

Rotate the signing secret using the **Rotate secret** action on the endpoint edit screen, or the console command:

```shell
./craft password-policy/webhook/rotate-secret 42
```

Either way:

1. The current secret moves to `secretPrevious` and a freshly generated secret becomes current.
2. The new plaintext is shown **once**, in a panel on the edit screen or on stdout. It is encrypted at rest and not recoverable afterwards, so capture it there or rotate again.
3. Through the grace window, the old secret remains stored so your receiver can still verify against it.
4. `RotateWebhookSecretJob` reaps the old secret once the window elapses.

The grace window exists for the receiver's benefit, not the plugin's. **The plugin signs with the new secret exclusively from the moment of rotation.** There is no header carrying a second signature, so a receiver that only knows the old secret starts failing verification immediately. Update your receiver during the window; the window buys you time to deploy, not dual-signing.

The window is set by `webhookSecretGracePeriodHours`, default **24 hours**, configurable up to 7 days. There is no per-rotation override.

## Circuit breaker

Each endpoint has a per-endpoint circuit breaker matching the [SIEM forwarder pattern](./siem-forwarders.md#circuit-breaker):

- **Closed state**: every delivery attempt runs.
- **Open state**: once consecutive failures reach the threshold, the breaker opens and subsequent runs skip the endpoint.
- **Half-open**: after the cooldown elapses, the endpoint rejoins the next sweep and the next dispatch is the probe.

Two settings control it, both without a control panel field:

| Setting | Default | Effect |
|---|---|---|
| `webhookCircuitFailureThreshold` | `5` | Consecutive failures that open the breaker. |
| `webhookCircuitCooldownSeconds` | `300` | Seconds a breaker stays open before the half-open probe. |

A response outside the 2xx range counts as a failure, and so does a redirect. The plugin never follows a 3xx, because that would re-POST the signed payload to a host you never registered.

Circuit state is stored durably in the `passwordpolicy_webhook_endpoints` table. A cache flush doesn't reset it.

The compliance dashboard's pending-forwards section covers SIEM forwarding only. For webhooks, the endpoints index is the operator surface: it carries the circuit pill and the sweep warning described below.

## CP management

### Endpoints index

**Password Policy → Webhooks** lists every endpoint in a table of:

- Name, linking to the edit screen
- URL
- Status pill (green when enabled, grey when disabled)
- Circuit pill (green when closed, red when open, with the consecutive-failure count inline)
- Last delivered row, as the audit row id the cursor sits on
- An **Edit** button

Test-firing, rotating a secret and resetting a circuit are all on the edit screen rather than the index.

It also carries the sweep warning. Because delivery only happens when you schedule `password-policy/webhook/run`, an install that never wired that cron entry up looks exactly like a working one from this screen: an enabled endpoint, a closed circuit, and no deliveries. So when an endpoint has a backlog behind its cursor that has been waiting more than two hours without ever being dispatched, the index says so, reports how many endpoints are affected, names the command, and reminds you a queue runner has to be draining the queue too.

The warning is deliberately quiet on anything that isn't a stopped sweep:

- A cursor that has caught up, no endpoint enabled, no endpoint allowlist covering the `audit_log` stream, or a fresh install: no warning. A new endpoint starts from the newest audit row, so it has no backlog to begin with.
- An endpoint with consecutive failures recorded, or one sitting on an open circuit: no warning. That is a delivery problem, not a cron problem, and it already shows in the Circuit column. One caveat: resetting the circuit on an endpoint that is genuinely refusing zeroes its failure counter, so that endpoint can report the cron warning for one sweep interval until the next dispatch fails.

The endpoint count is the useful part of the message: one endpoint behind points at that endpoint, all of them behind points at the sweep. Two hours is roughly twenty-four consecutive missed sweeps at the documented five-minute cadence, and it is not configurable: the window only affects when the warning appears, never what gets delivered.

### Endpoint edit screen

One screen, in sections:

- **General**: name, URL, enabled.
- **Eligibility**: the per-endpoint event class allowlist.
- **HMAC secret**: rotation state, and the **Rotate secret** button behind a confirmation step. This section only renders on an endpoint that has been saved.
- **Circuit breaker**: current circuit state, the cursor's last delivered row id, and the **Reset circuit** and **Send test event** buttons.

On the first render of a newly created endpoint's edit screen, a panel at the top carries the generated secret. It is shown that once and never again. `./craft password-policy/webhook/create` prints it to stdout instead, which is the easier path to capture from a provisioning script.

### Send test event

**Send test event** writes a real `webhook_test` row to the audit log and POSTs it to this endpoint synchronously, then reports the response status code and the round-trip duration inline. On a failure it also shows a bounded excerpt of the status line and response body.

Three things follow from that:

- The test row is a real audit row. It stays in the audit log, and other endpoints and the SIEM forwarder will deliver it too.
- A test fire does not move the endpoint's cursor. It is a direct dispatch, not a sweep.
- A test fire counts towards the circuit breaker like any other dispatch. A failing test increments the failure counter, and a succeeding one clears it.

There is no stored delivery history in the control panel. For per-delivery observability across every dispatch, subscribe to `EVENT_WEBHOOK_DELIVERY_ATTEMPT`, which fires on success and failure alike and carries the status code, duration and error message. See [Events](../reference/events.md).

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
    --name="Compliance dashboard"
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
| `pp:webhooks-manage` | Full CRUD on endpoints + test-fire + rotate-secret + reset-circuit actions. Enterprise-only. |

## Use cases

Every endpoint receives every audit row, so the routing decision belongs to your receiver. It reads the body's `event` key and does what it likes with it.

- **Slack channel for security alerts**: the receiver keeps `hibp_breach_detected`, `account_locked` and `policy_changed`, drops the rest, and formats what's left into a readable message for Slack's own webhook URL.
- **SOC integration**: internal SOC API takes everything, classifies events as critical, medium or low, and routes to the right on-call channel.
- **Compliance vendor**: a small adapter forwards `password_changed`, `policy_changed` and `account_locked` into a third-party compliance platform for evidence collection.
- **Audit retention archive**: long-term storage of every event in S3 via an API Gateway to Lambda to S3 pipeline. Combine with retention purge on the plugin side: the warehouse keeps the long history; the plugin keeps the operational window.

## See also

- [Audit logging](./audit-logging.md): the source of audit events that get delivered, and what each body key means.
- [SIEM forwarders](./siem-forwarders.md): syslog-over-TLS delivery with at-least-once-to-one semantics, for collectors that speak syslog.
- [Audit verifier](./audit-verifier.md): proving the source-side hash chain hasn't been tampered with.
- [Audit export](./audit-export.md): batch export to filesystem for offline analysis.
- [Events](../reference/events.md): `EVENT_WEBHOOK_DELIVERY_ATTEMPT` fires on every delivery attempt for custom monitoring integrations.
