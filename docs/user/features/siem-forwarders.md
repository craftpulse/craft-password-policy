# SIEM Forwarders (Enterprise)

Enterprise installs can forward every audit row to one or more SIEM endpoints — Splunk HEC, Datadog Logs, generic syslog-over-TLS receivers (Graylog, IBM QRadar, rsyslog, syslog-ng), or any HTTP-based ingestion path. The forwarder ships TLS by default, an HMAC-signed delivery model, a per-endpoint circuit breaker, and at-least-once delivery semantics.

> 📷 *Screenshot: Forwarders index page showing three configured forwarders — "Splunk Production" (green-status), "Datadog Logs" (green-status), "Graylog Backup" (amber-status with "Circuit open: 3 consecutive failures"). Each row shows endpoint URL, protocol, last-delivery timestamp, and consecutive-failure count.*

This page covers configuring forwarders, the supported protocols, the at-least-once delivery model, the circuit breaker, the audit-row format on the wire, and troubleshooting common issues.

## Quick start

1. Open **Password Policy → Forwarders → New forwarder** in the control panel.
2. Pick a protocol: **Syslog over TLS** for traditional SIEMs, or **HTTP** for SaaS log platforms.
3. Configure the destination URL + auth headers (for HTTP) or host + port (for syslog).
4. Save. The first audit-row write after save triggers a forwarder run that delivers the unforwarded backlog.

The forwarder works on a watermark model — every audit row tracks whether it's been delivered (`forwardedAt` column). New rows are delivered on the next forwarder run; backlogs are caught up automatically.

## Supported protocols

### Syslog over TLS (`syslog-tls`)

The native protocol for traditional SIEMs. RFC 5424 framing over a TLS socket on the standard IANA port (6514) or a custom port.

| Setting | Required | Example |
|---|---|---|
| Host | Yes | `siem.acme.internal` |
| Port | Yes | `6514` |
| TLS CA bundle path | No (defaults to system) | `/etc/ssl/certs/siem-ca-bundle.pem` |
| Facility | No (defaults to `local0`) | `local0` … `local7` |
| Hostname identifier | No (defaults to `gethostname()`) | `craft-prod` |

The TLS connection uses Craft's default trust store unless you set a custom CA bundle. The plugin enforces `verify_peer => true` and `verify_peer_name => true` — disabling peer verification requires editing the service code, intentionally.

Compatible with rsyslog, syslog-ng, Graylog (via the GELF TLS input), IBM QRadar, and any SIEM that accepts RFC 5424 messages over TLS.

### HTTP (`http`)

For SaaS log platforms that ingest over HTTPS. POST JSON to a configured URL with optional custom headers for auth.

| Setting | Required | Example |
|---|---|---|
| URL | Yes | `https://http-intake.logs.datadoghq.com/api/v2/logs` |
| Custom headers | No | `DD-API-KEY: your-key-here` (one per line) |
| Method | No (defaults to POST) | `POST` |

The HTTP destination uses Guzzle with `verify => true` enforced at the request site (overrides any site-level `config/guzzle.php` setting). Request timeout defaults to 10 seconds; configurable per forwarder.

**Specific destination configurations** are documented in [Supported destinations](#supported-destinations) below.

## Supported destinations

The wire format is the same across destinations — only the transport class (syslog-tls vs HTTP) and the auth/header config differ. Buyers searching by name:

### Splunk HEC (HTTP Event Collector)

- **Protocol:** HTTP
- **URL:** `https://<your-splunk>/services/collector/event`
- **Custom headers:** `Authorization: Splunk <your-HEC-token>`
- **Optional:** `X-Splunk-Request-Channel: <channel-uuid>` for per-stream tracking

Splunk HEC accepts JSON over POST and returns a `200 OK` with `{"text": "Success", "code": 0}` on accept. The plugin treats any non-2xx response as a delivery failure for circuit-breaker purposes.

### Datadog Logs

- **Protocol:** HTTP
- **URL:** `https://http-intake.logs.datadoghq.com/api/v2/logs` (or `eu.datadoghq.com` / regional equivalent)
- **Custom headers:** `DD-API-KEY: <your-datadog-api-key>`

Datadog accepts JSON arrays and the plugin sends individual events as single-element arrays for compatibility.

### Sumo Logic HTTP Source

- **Protocol:** HTTP
- **URL:** Your collector URL (the URL itself embeds the source ID, no auth header required)
- **Custom headers:** None required

### Generic HTTP-based SIEM

Any platform that accepts JSON over POST with configurable headers works through the same HTTP destination class:

- NewRelic Logs API
- Logstash HTTP input
- Elastic ingest pipelines
- Fluentd HTTP input
- Custom internal ingestion endpoints

Point the URL + configure the headers — the rest is transparent.

### Graylog, rsyslog, syslog-ng, IBM QRadar

- **Protocol:** Syslog over TLS
- **Port:** 6514 (or your configured listener)
- **Auth:** TLS peer verification (configure the CA bundle on your SIEM)

These accept RFC 5424 framed messages over TLS directly.

## Wire format

Each audit row produces one structured-data message containing the canonical JSON of the row plus standard syslog or HTTP framing.

### Syslog over TLS

```
<14>1 2026-05-15T03:33:14.123Z craft-prod password-policy 12345 audit_row [pp@32473 event="password_changed" rowId="8821"] {"event":"password_changed","userIdentifier":"a3f4b...","userId":42,"ipHash":"c91d7...","outcome":"success","details":{...},"previousHash":"...","rowHash":"...","dateCreated":"2026-05-15T03:33:14Z"}
```

- **PRI**: `14` (`local0.info` by default; configurable).
- **VERSION**: `1` (RFC 5424).
- **TIMESTAMP**: UTC ISO 8601 with millisecond precision.
- **HOSTNAME**: Configured hostname identifier.
- **APP-NAME**: `password-policy`.
- **PROCID**: The audit row's `id`.
- **MSGID**: `audit_row`.
- **STRUCTURED-DATA**: PEN-anchored `pp@32473` element with `event` and `rowId` keys.
- **MSG**: The canonical JSON of the audit row (same bytes that go into the hash chain).

The PEN (`32473`) is a private enterprise number reserved for examples. Production deployments should request their own from IANA if they need a vendor-specific PEN.

### HTTP

```json
{
    "event": "password_changed",
    "userIdentifier": "a3f4b...",
    "userId": 42,
    "ipHash": "c91d7...",
    "outcome": "success",
    "details": {...},
    "previousHash": "...",
    "rowHash": "...",
    "dateCreated": "2026-05-15T03:33:14Z",
    "_meta": {
        "rowId": 8821,
        "hostname": "craft-prod",
        "pluginVersion": "5.2.0"
    }
}
```

The body is the canonical JSON plus a `_meta` envelope with operational fields the receiving SIEM may want for routing/filtering.

## At-least-once delivery semantics

The plugin uses a watermark model with at-least-once-to-one semantics across multiple endpoints:

1. The `forwardedAt` column on each audit row is `NULL` when the row hasn't been delivered to any endpoint.
2. `SiemForwardJob` (a `BaseBatchedJob`) reads unforwarded rows in batches of 100 from `UnforwardedAuditRowBatcher`.
3. For each row, the job attempts delivery to every configured endpoint in sequence.
4. The row counts as **forwarded** the moment ONE endpoint returns success — `forwardedAt` is stamped.
5. Failed endpoints retry on the next forwarder run; the row's `forwardedAt` doesn't roll back.

The trade-off: a SIEM that's slow to come back online will miss some events while it's down. Operators running redundant SIEMs (Splunk + a secondary Graylog as cold backup) accept this — the primary captures everything; the cold backup may have gaps during the primary's downtime windows.

For per-endpoint at-least-once delivery (every endpoint receives every row independently), use [Webhooks](./webhooks.md) instead — webhook endpoints use a per-endpoint watermark via `lastDeliveredRowId`.

## Circuit breaker

Each forwarder has a per-endpoint circuit breaker to prevent cascading failures from blocking the queue:

- **Closed state** (normal): Every forwarder run attempts delivery.
- **Open state**: After 5 consecutive failures, the breaker opens. Subsequent forwarder runs skip this endpoint and increment `consecutiveFailures`.
- **Half-open state**: After 5 minutes in the open state, the next forwarder run attempts a single delivery. Success → closed; failure → back to open with the timer reset.

Circuit state is durably stored in the `siem_forwarders` table (`consecutiveFailures` + `circuitOpenAt` columns) so a cache flush doesn't reset the breaker.

The dashboard's **Pending SIEM forwarding** section surfaces broken circuits with the oldest-pending-row age — operators can spot a stuck forwarder before the backlog grows.

## CP management

### Forwarders index

**Password Policy → Forwarders** lists every configured forwarder with:

- Name + protocol
- Endpoint URL/host
- Status pill (Green: healthy, Amber: circuit open or recent failures, Grey: disabled)
- Last delivery timestamp
- Consecutive-failure count
- Edit + Delete actions

### Forwarder edit screen

Two tabs:

- **Configuration** — protocol-specific fields (URL, headers for HTTP; host, port, CA bundle for syslog-tls).
- **Test event** — a button that sends a synthetic audit row to the endpoint and surfaces the response inline. Useful for validating credentials/connectivity without waiting for real audit traffic.

> 📷 *Screenshot: Forwarder edit screen on Configuration tab — Splunk HEC URL field, custom-headers textarea showing the Authorization header, the Test event button at the bottom with an "Awaiting test" state.*

### Reset circuit

Each forwarder with an open circuit gets a **Reset circuit** action on the index. Clicking it manually closes the breaker — useful after fixing the underlying issue on the SIEM side.

## Console commands

```bash
# Trigger an immediate forwarder run (catches up the backlog)
./craft password-policy/siem/run

# Send a test event to a specific forwarder
./craft password-policy/siem/test --forwarder=<id>

# Reset a forwarder's circuit breaker
./craft password-policy/siem/reset-circuit --forwarder=<id>
```

## Permissions

| Permission | What it grants |
|---|---|
| `pp:siem-manage` | Full CRUD on forwarders + test-event + reset-circuit actions. Enterprise-only. |

## Troubleshooting

### Forwarder shows "Pending: 3,247 rows, oldest 4 hours"

The forwarder is stuck. Check:

1. **Circuit state** on the forwarder index — is the circuit open?
2. **Endpoint URL** — does the URL still resolve? Manual `curl` from the Craft host.
3. **Auth credentials** — has the SIEM rotated tokens? Click **Test event** on the edit screen.
4. **TLS bundle** — for syslog-tls forwarders, has the SIEM rotated its certificate? Update the CA bundle path.

After fixing the underlying issue, click **Reset circuit** to resume delivery.

### Test event fails with "Connection refused"

Network-level issue. Check:

1. **Firewall** — outbound traffic from Craft host to the SIEM endpoint allowed?
2. **DNS** — does the endpoint hostname resolve from the Craft host?
3. **Port** — is the SIEM listening on the configured port?

### Splunk HEC returns 403 "Token disabled"

HEC token is invalid or disabled. Generate a new token in Splunk and update the **Custom headers** field on the forwarder edit screen.

### Datadog API returns 413 "Request entity too large"

Audit row payloads should be well under Datadog's per-event size limit (5 MB). If you're hitting this, a row's `details` JSON is likely larger than expected — check what's being captured. This is rare but worth flagging as a defensive check.

## See also

- [Audit logging](./audit-logging.md) — the source of the audit rows that get forwarded.
- [Webhooks](./webhooks.md) — alternative HMAC-signed delivery with per-endpoint at-least-once semantics.
- [Compliance Dashboard](./compliance-dashboard.md) — Pending SIEM forwarding section + status drilldown.
- [Audit export](./audit-export.md) — batch export to filesystem for offline analysis.
- [Events](../reference/events.md) — `EVENT_SIEM_FORWARD_ATTEMPT` fires on every forwarder attempt for custom monitoring integrations.
