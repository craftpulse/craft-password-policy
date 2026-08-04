# SIEM Forwarders (Enterprise)

Enterprise installs can forward every audit row to one or more SIEM destinations. There are two transports, and each forwarder picks one:

- **Syslog over TLS** writes an RFC 5424 message per row to a `tls://` socket. This is the transport for a collector you run.
- **HTTP** POSTs the same canonical JSON to an HTTPS collector, with an optional `Authorization` header and any custom headers your platform needs.

Both ship TLS peer verification on by default, a per-destination circuit breaker, and at-least-once delivery semantics.

This page covers configuring forwarders on either transport, what the HTTP transport does and does not reach, event eligibility, the at-least-once delivery model, the circuit breaker, the audit-row format on the wire, and troubleshooting.

## Quick start

1. Open **Password Policy → SIEM forwarders → New forwarder** in the control panel.
2. Pick a **Protocol**.
   - For **Syslog over TLS**, enter the receiver's **Host** and **Port**. Port 6514 is prefilled.
   - For **HTTP**, enter the collector's **Endpoint URL** and, if it needs one, an **Authentication** type and **Credential**.
3. Save.
4. Put `password-policy/siem/run` on a cron schedule and make sure a queue runner is running. Nothing is forwarded until both are in place, see [Console commands](#console-commands) below.

The forwarder works on a watermark model: every audit row tracks whether it's been delivered (`forwardedAt` column). New rows are delivered on the next forwarder run; backlogs are caught up automatically.

## Forwarder fields

Three fields are shared by both transports, and the rest depend on the protocol you pick.

| Field | Required | Notes |
|---|---|---|
| Name | No | Display label, for example "Central rsyslog". The index falls back to the destination when it's empty. |
| Protocol | Yes | **Syslog over TLS** or **HTTP**. |
| Enabled | Yes | On by default. Disabled forwarders are skipped by the queue job entirely. |
| Custom CA bundle path | No | Path to a PEM CA bundle, for example `/etc/ssl/certs/siem-ca-bundle.pem`. Accepts an environment variable reference such as `$PP_SIEM_CA_BUNDLE`. Honoured by both transports. |
| Event class allowlist | No | Empty means "use the global setting". See [Event eligibility](#event-eligibility). |

## Syslog over TLS

The plugin opens a `tls://` stream socket to the configured host and port and writes one RFC 5424 message per audit row.

This reaches rsyslog, syslog-ng, Graylog, IBM QRadar, and any collector with a TLS syslog listener, including a self-hosted Splunk indexer configured with a TCP-SSL input.

| Field | Required | Notes |
|---|---|---|
| Host | Yes | The receiver's hostname or IP, for example `siem.acme.internal`. |
| Port | Yes | Prefilled with `6514`, the IANA registered port for syslog over TLS. |
| Message framing | Yes | **Octet-counted (RFC 5425)** by default, or **Newline-delimited**. See below. |
| Verify TLS certificate | No | On by default. |

The connection verifies the receiver's certificate chain against the system trust store unless you point **Custom CA bundle path** at your own bundle. Turning **Verify TLS certificate** off disables peer and peer-name verification together, so use it only against a receiver you trust by network path.

Timeouts are not configurable. The connect timeout is 5 seconds, and the same bound applies to the write, which is what turns a receiver that accepts the connection but never drains the frame into a recorded failure instead of a stalled queue job.

### Message framing

RFC 5425 §4.3 defines the TLS transport mapping for syslog as `MSG-LEN SP SYSLOG-MSG`, and §4.3.1 requires a transport receiver to use that length to delimit each message. **Octet-counted** does exactly that: the message is prefixed with its own byte count and a space, and nothing follows it.

```
70 <133>1 2026-05-15T03:33:14Z craft-prod password-policy 4821 audit-log - {...}
```

**Newline-delimited** appends a `\n` to each message instead, with no length prefix. That is RFC 6587-style non-transparent framing, and it is what rsyslog's `imtcp` accepts by default.

Pick octet counting unless your receiver expects line-delimited input. Both are common: rsyslog with `SupportOctetCountedFraming` on (its default) accepts either, while a strict RFC 5425 receiver accepts only the octet-counted form. Getting it wrong is quiet from this side, because syslog has no application-level acknowledgement, so confirm on the receiver after switching.

## HTTP

The plugin POSTs the canonical JSON of each audit row to the configured URL, one request per row.

| Field | Required | Notes |
|---|---|---|
| Endpoint URL | Yes | The collector's HTTPS URL. Accepts an environment variable reference such as `$PP_SIEM_URL`. |
| Authentication | Yes | **None**, **Bearer token**, or **Basic**. |
| Credential | When authentication is not None | Sent as the `Authorization` header. Encrypted at rest, and never shown again after saving. Accepts an environment variable reference such as `$PP_SIEM_TOKEN`. |
| Custom headers | No | Name and value pairs added to every request. Values accept environment variable references. |

What the request looks like:

| Part | Value |
|---|---|
| Method | `POST` |
| `Content-Type` | `application/json`, always. It cannot be overridden. |
| `Authorization` | `Bearer <credential>` for Bearer, `Basic <base64 of the credential>` for Basic, absent for None. For Basic, enter the credential as `user:password`; the plugin base64-encodes it. |
| Other headers | Whatever you add under **Custom headers**. |
| Body | The audit row as canonical JSON, byte-identical to the syslog message payload and to the webhook body. See [Payload](#payload). |
| Timeout | 10 seconds total, covering connect, TLS handshake, send, and receive. Not configurable. |

Four things about this transport are deliberate and not configurable:

- **HTTPS only.** A plain `http://` URL is refused when you save, and a URL that comes from an environment variable is re-checked when the row is forwarded, so an env var pointing at `http://` fails there instead of leaking a credential. **Verify TLS certificate** applies to the syslog transport only: an HTTP forwarder always verifies, because it carries a credential.
- **Redirects are never followed.** A 3xx counts as a failure. Following one would re-POST the audit row and the credential to whatever host the response names.
- **Only a 2xx counts as delivered.** Everything else, including a 3xx, increments the failure counter.
- **`Content-Type`, `Content-Length`, `Host`, `Transfer-Encoding`, and `Connection` cannot be set through Custom headers**, and `Authorization` is only accepted there when **Authentication** is None. That combination is how you send a vendor's own scheme, for example `Authorization: Splunk <token>`.

An environment variable that isn't set resolves to the literal `$NAME` string. Rather than sending that, the forward fails and names the field in the plugin log, so a missing variable looks like a configuration problem instead of an authentication failure from the far end.

### What the HTTP transport reaches

The body is the audit row and nothing else. There is no vendor envelope around it, and no per-destination payload format to choose.

| Destination | Reachable |
|---|---|
| A collector or gateway you write, an HTTP source that accepts arbitrary JSON (for example a Sumo Logic HTTP Logs and Metrics source), a Logstash `http` input, or an Elasticsearch-compatible endpoint that takes a JSON document | **Yes.** Point the URL at it, add whatever header it authenticates with, done. |
| Splunk HTTP Event Collector | **No.** HEC expects its own event wrapper around the payload, which the plugin does not build. |
| Datadog Logs intake | **No.** Its API expects an array of log items, not a single JSON object. |
| Microsoft Sentinel Logs Ingestion API | **No.** It expects an array shaped to a Data Collection Rule, and its bearer token has to be minted and refreshed through Microsoft Entra rather than stored. |

For the three in the "No" column, the shape of the request is right and the shape of the body is not, so the integration needs something that reshapes it: a small relay of your own, or a vendor-supplied agent such as Splunk Connect for Syslog in front of the syslog transport.

## Event eligibility

A forwarder only receives audit rows when its eligible event classes include the `audit_log` stream. Two layers decide that:

- **`siemForwardEventClasses`**, a plugin setting, is the global default. It ships as `['audit_log']` and there is no control panel field for it. Set it in `config/password-policy.php` if you need to change it.
- The **Event class allowlist** field on each forwarder overrides the global setting for that row when it's non-empty.

`audit_log` is the only supported stream in 5.2.0. The field exists because the shape is forward-compatible with future streams, not because there is a second value to pick today.

> [!WARNING]
> **An allowlist that doesn't name `audit_log` delivers nothing, silently**
>
> A forwarder whose eligible classes exclude `audit_log` is never offered a row. It is not a failure, so nothing increments `forwardAttempts`, the circuit stays closed, the status pill stays green, and no warning appears anywhere. The forwarder simply never receives anything.
>
> Leave the field empty unless you have a reason not to. If you fill it in, `audit_log` has to be in the list.

## At-least-once delivery semantics

The plugin uses a watermark model with at-least-once-to-one semantics across multiple endpoints:

1. The `forwardedAt` column on each audit row is `NULL` when the row hasn't been delivered to any endpoint.
2. `password-policy/siem/run` enqueues `SiemForwardJob` (a `BaseBatchedJob`), which reads unforwarded rows in batches of 100, oldest first. That command is the only trigger, so it belongs in cron.
3. For each row, the job attempts delivery to every active forwarder in sequence.
4. The row counts as **forwarded** the moment ONE forwarder accepts it, at which point `forwardedAt` is stamped.
5. When no forwarder accepts, `forwardAttempts` increments and `forwardedAt` stays empty, so the next run retries the row.

Note what that means on the first sweep after you configure your first forwarder: `forwardedAt` is empty on every row already in the audit log, so all of them are pending and all of them are forwarded, oldest first. On an install that has been collecting audit events for months, that is a large first pass. It is bounded by the audit log's own retention window, it is batched at 100 rows per slice, and it happens once. If you would rather not ship that history, purge to the window you want to keep with `./craft password-policy/audit/purge --days=<n>` before you schedule the sweep. Webhook endpoints behave differently: they start from the newest row at creation and never replay history.

The trade-off: with more than one forwarder configured, a receiver that's slow to come back online misses whatever another forwarder accepted while it was down. Operators running a redundant collector accept this. The primary captures everything, and the cold backup may have gaps across the primary's downtime windows.

For per-endpoint at-least-once delivery, where every endpoint receives every row independently, use [Webhooks](./webhooks.md) instead: webhook endpoints keep a per-endpoint watermark in `lastDeliveredRowId`.

## Wire format

On the syslog transport, each audit row produces one RFC 5424 message. On the HTTP transport the same JSON is the whole request body, with no header fields and no envelope around it.

```
<133>1 2026-05-15T03:33:14Z craft-prod password-policy 4821 audit-log - {"changedByIdentifier":null,"changedByUserId":null,"dateCreated":"2026-05-15 03:33:14","details":"{\"source\":\"front-end-change\"}","event":"password_changed","forwardAttempts":0,"forwardedAt":null,"geoCountry":null,"geoRegion":null,"id":8821,"ipHash":"c91d7...","outcome":"success","previousHash":"...","rowHash":"...","source":"web","uid":"6f7e8d9c-1234-5678-9abc-def012345678","userId":42,"userIdentifier":"a3f4b..."}
```

Header field by field:

- **PRI**: `133`, which is facility `local0` with severity `notice`. Not configurable.
- **VERSION**: `1`.
- **TIMESTAMP**: the moment the message was built, UTC, second precision, with a literal `Z`. It is not the row's `dateCreated`.
- **HOSTNAME**: the Craft host's own `gethostname()`. Not configurable.
- **APP-NAME**: `password-policy`.
- **PROCID**: the id of the PHP process that built the message.
- **MSGID**: `audit-log`.
- **STRUCTURED-DATA**: `-`. The plugin sends no structured-data elements.
- **MSG**: the audit row as canonical JSON. What surrounds it on the stream is the [message framing](#message-framing): a leading octet count, or a trailing newline.

### Payload

The payload is the whole audit-log row, encoded by the same canonicaliser that feeds the hash chain: keys sorted recursively as strings, with unescaped slashes and unescaped unicode. The keys are:

`changedByIdentifier`, `changedByUserId`, `dateCreated`, `details`, `event`, `forwardAttempts`, `forwardedAt`, `geoCountry`, `geoRegion`, `id`, `ipHash`, `outcome`, `previousHash`, `rowHash`, `source`, `uid`, `userId`, `userIdentifier`.

Two things to know before writing a parser against it:

- **`details` arrives as a JSON string, not a nested object.** The column value is passed through verbatim, so it reads as `"{\"source\":\"admin\"}"`. Field extraction that expects nested keys needs a decode step first.
- **`dateCreated` is the raw column value**, `YYYY-MM-DD HH:MM:SS` in UTC, not ISO 8601.

`forwardedAt` is always `null` on the wire, because a row is only offered to a forwarder while it is unforwarded.

The payload is a wider key set than the hash chain covers. The chain hashes nine keys (`changedByIdentifier`, `dateCreated`, `details`, `event`, `ipHash`, `outcome`, `source`, `uid`, `userIdentifier`) with `details` as a decoded object, so recomputing `rowHash` from what arrives on the wire will not reproduce the stored value. For chain verification, run the [audit verifier](./audit-verifier.md) against the source install. See [Audit logging](./audit-logging.md) for what each column means and which of them are identifying.

All three surfaces carry the same bytes: the syslog MSG, the HTTP transport's request body, and a webhook delivery's request body, so a receiver written against one parses the others. The two can disagree on `forwardedAt` and `forwardAttempts`, which track forwarder progress and therefore depend on which sweep read the row first.

## Circuit breaker

Each forwarder has a per-endpoint circuit breaker to prevent a dead receiver from blocking the queue:

- **Closed state** (normal): every forwarder run attempts delivery.
- **Open state**: once consecutive failures reach the threshold, the breaker opens and subsequent runs skip this forwarder.
- **Half-open state**: after the cooldown elapses, the forwarder rejoins the next batch and the next delivery attempt is the probe. Success closes the circuit; failure pushes the open timestamp forward.

Two settings control it, both without a control panel field:

| Setting | Default | Effect |
|---|---|---|
| `siemCircuitFailureThreshold` | `5` | Consecutive failures that open the breaker. |
| `siemCircuitCooldownSeconds` | `300` | Seconds a breaker stays open before the half-open probe. |

Circuit state is stored durably on the `passwordpolicy_siem_forwarders` row (`consecutiveFailures` + `circuitOpenAt`), so a cache flush doesn't reset the breaker.

The compliance dashboard's **Pending SIEM forwarding** section reports how many audit rows are still unforwarded and how old the oldest one is, with a link through to the forwarders index. That is the earliest place a stuck forwarder shows up, as a number that keeps growing.

## CP management

### Forwarders index

**Password Policy → SIEM forwarders** lists every configured forwarder in a table of:

- Name, linking to the edit screen
- Endpoint: `host:port` on a syslog forwarder, the URL on an HTTP one
- Protocol
- Status pill (green when enabled, grey when disabled)
- Circuit pill (green when closed, red when open, with the consecutive-failure count inline)
- An **Edit** button

It also carries the sweep warning. Because forwarding only happens when you schedule `password-policy/siem/run`, an install that never wired that cron entry up looks exactly like a working one from this screen: an enabled forwarder, a closed circuit, and no deliveries. So when an audit row has been waiting more than two hours for a first delivery attempt, the index says so, names the command, and reminds you a queue runner has to be draining the queue too.

The warning is deliberately quiet on anything that isn't a stopped sweep:

- Nothing pending, no forwarder enabled, no forwarder allowlist covering the `audit_log` stream, or an empty audit log: no warning. An install with no forwarder leaves `forwardedAt` empty on every row forever, and that is the correct steady state of an idle install rather than a fault.
- Rows that were attempted and refused: no warning. That is a forwarder problem, not a cron problem, and it already shows in the Circuit column and the failure counter. Same for a forwarder sitting on an open circuit.

Two hours is roughly twenty-four consecutive missed sweeps at the documented five-minute cadence. It is not configurable: the window only affects when the warning appears, never what gets forwarded.

### Forwarder edit screen

One screen, in sections. Which fields the **Destination** section shows follows the **Protocol** you pick, and switching it swaps them immediately.

- **General**: name, protocol, enabled.
- **Destination**: host, port, and message framing on syslog; endpoint URL, authentication, credential, and custom headers on HTTP.
- **TLS**: the certificate verification toggle (syslog only) and the custom CA bundle path (both transports).
- **Eligibility**: the per-forwarder event class allowlist.
- **Circuit breaker**: current circuit state, plus the **Reset circuit** and **Send test event** buttons. This section only renders on a forwarder that has been saved.

Switching a saved forwarder from HTTP to syslog clears its URL, authentication type, credential, and custom headers in the same save, so a credential is never left behind for a destination the forwarder no longer talks to. The reverse switch clears host and port.

### Send test event

**Send test event** writes a real `siem_test` row to the audit log and forwards it to this forwarder synchronously, then reports the outcome as a control panel notice.

Three things follow from that:

- The test row is a real audit row. It stays in the audit log, and webhook endpoints will deliver it too.
- On the syslog transport there is no application-level acknowledgement, so "Test event delivered." means the message was written to the socket without error. It does not prove the receiver parsed or indexed it. Confirm that on the receiver. The HTTP transport is stricter: it only reports success on a 2xx response.
- A test event counts towards the circuit breaker like any other forward. A failing test increments the failure counter, and a succeeding one clears it.

Connection-level detail is deliberately kept out of the response, because raw transport errors carry internal hostnames, IPs and ports. When a test fails, the reason is in the plugin log, including the response status and a bounded slice of the response body on the HTTP transport.

### Reset circuit

**Reset circuit** on the edit screen clears `circuitOpenAt` and zeroes the failure counter immediately, which saves waiting out the cooldown after you've fixed the problem on the receiver's side.

## Console commands

One command, and it is the one that makes forwarding happen:

```shell
./craft password-policy/siem/run
```

It enqueues `SiemForwardJob` for the rows waiting to be forwarded. Two of the operator actions stay in the control panel:

| Action | Where |
|---|---|
| Send a test event to one forwarder | The **Circuit breaker** section of the forwarder's edit screen. |
| Close an open circuit breaker | The **Reset circuit** button in the same section. |

> [!WARNING]
> **Forwarding needs a cron entry and a queue runner**
>
> Two separate things have to be running, and a forwarder configured without both delivers nothing while reporting no error.
>
> `password-policy/siem/run` is what puts `SiemForwardJob` on the queue. Nothing else does: no request hook, no garbage-collection pass, no control panel action. Without that command on a schedule, every audit row keeps an empty `forwardedAt` forever. The forwarder index warns once the oldest such row is more than two hours old, so this is no longer silent, but the warning is a backstop and not a substitute for the cron entry.
>
> A queue runner is what executes the job once it is queued. If your install relies on Craft's default web-request-triggered runner and the site is quiet, the backlog will sit still even with the cron in place, and the index warning will eventually appear for that reason too. Run the queue from cron as well (`./craft queue/listen` under a process supervisor, or `./craft queue/run` on a schedule).
>
> See [Cron setup](../operations/cron-setup.md) for both entries.

## Permissions

| Permission | What it grants |
|---|---|
| `pp:siem-manage` | Full CRUD on forwarders + test-event + reset-circuit actions. Enterprise-only. |

## Troubleshooting

### Pending count is large and the oldest row is hours old

Work through these in order:

1. **Is the sweep scheduled?** A missing `password-policy/siem/run` cron entry is the most common cause, and it is what the index warning is pointing at.
2. **Is a queue runner draining the queue?** `./craft queue/info` shows what's waiting.
3. **Is the circuit open?** Check the Circuit column on the index. An open circuit with a failure count means the receiver is refusing or timing out, which is a receiver problem rather than a cron problem.
4. **Does the forwarder's allowlist include `audit_log`?** An allowlist that excludes it produces zero deliveries and zero failures, so it looks healthy from the index.

After fixing the underlying issue, use **Reset circuit** to resume delivery without waiting out the cooldown.

### Test event fails on a syslog forwarder

The message in the control panel is deliberately generic. The actual exception is in the plugin log (`storage/logs/password-policy-*.log`). Common causes:

1. **Firewall**: outbound traffic from the Craft host to the receiver's port is blocked.
2. **DNS**: the host doesn't resolve from the Craft host.
3. **Port**: the receiver isn't listening on the configured port, or is listening for plain TCP rather than TLS.
4. **Certificate**: the receiver's chain doesn't verify against the system trust store. Point **Custom CA bundle path** at the issuing CA rather than turning verification off.
5. **Half-open peer**: the receiver accepts the connection but never drains the message. This surfaces as a write timeout after 5 seconds.

### Test event fails on an HTTP forwarder

The plugin log carries the response status and a bounded slice of the response body, which is usually enough on its own. Common causes:

1. **401 or 403**: the credential is wrong, or the collector wants it in a header rather than in `Authorization`. Set **Authentication** to None and add the vendor's header under **Custom headers**.
2. **400 or 422**: the collector accepted the request but rejected the body, which usually means it wants a vendor envelope the plugin does not build. See [What the HTTP transport reaches](#what-the-http-transport-reaches).
3. **A 3xx in the log**: the URL redirects. Redirects are never followed, so point the forwarder at the final URL.
4. **"The resolved endpoint URL is not https://"**: the URL, or the environment variable it resolves to, is plain http.
5. **"The forwarder auth token is empty once resolved"** or **"The … header is empty once resolved"**: an environment variable named in that field isn't set in this environment.
6. **A TLS error**: the collector's chain doesn't verify. Point **Custom CA bundle path** at the issuing CA. There is no verification opt-out on this transport.

### The receiver connects but logs nothing usable

1. **Framing**: the receiver and the forwarder's **Message framing** disagree. A listener requiring octet counting discards newline-delimited messages, and a listener reading line-delimited input sees the octet count as part of the message. See [Message framing](#message-framing).
2. **`details` is a string**: parsers expecting a nested object see a quoted JSON string. See [Payload](#payload).
3. **Message size**: a row with an unusually large `details` blob makes for a long message. Check what's being captured if your receiver truncates.

## See also

- [Audit logging](./audit-logging.md): the source of the audit rows that get forwarded, and what each column means.
- [Webhooks](./webhooks.md): HMAC-signed HTTPS delivery with per-endpoint at-least-once semantics, and a signature a receiver can verify. Use it over the HTTP transport here when the receiver is yours and you want the payload signed, or when you need every endpoint to receive every row independently.
- [Audit verifier](./audit-verifier.md): proving the source-side hash chain hasn't been tampered with.
- [Compliance Dashboard](./compliance-dashboard.md): the pending-forwarding count and oldest-pending age.
- [Audit export](./audit-export.md): batch export to filesystem for offline analysis.
