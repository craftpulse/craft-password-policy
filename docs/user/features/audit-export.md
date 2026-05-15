# Audit Export (Enterprise)

Enterprise installs can export the audit log to CSV or JSONL for offline analysis, evidence packages, or long-term archival. The export utility supports synchronous downloads for small ranges, queued background jobs for large date spans, any Craft filesystem as the destination, and per-admin download tokens to prevent URL leak across CP admins.

> 📷 *Screenshot: Audit Export utility under Utilities, showing the date range picker (preset of "Last 30 days"), the format selector (CSV / JSONL), the destination dropdown (local runtime / configured S3 filesystem), and the Run export button.*

This page covers the export utility, format choices, filesystem destinations, the per-admin download model, the queued job workflow for large exports, and common evidence-package recipes.

## Quick start

1. Open **Utilities → Audit Export** in the control panel.
2. Pick a date range — preset windows (last 7 / 30 / 90 days, all time) or a custom range.
3. Pick a format — **CSV** (spreadsheet-friendly, RFC 4180 quoting) or **JSONL** (one canonical JSON object per line, idiomatic for log-processing tools).
4. Click **Run export**.

For ranges under 1,000 rows, the file streams directly to your browser. For larger ranges, the export is queued; you'll receive a one-time download link via the `password-policy:audit-export-ready` email when the job completes.

## Synchronous vs queued

The utility picks between two execution paths based on the row count:

| Row count | Path | UX |
|---|---|---|
| ≤ 1,000 rows | Synchronous stream | File downloads immediately in the browser. |
| > 1,000 rows | Queued `AuditExportJob` | The utility shows a "queued" flash and the email arrives when done. |

The 1,000-row threshold balances PHP memory budget (a synchronous CSV of ~1 MB is fine) against the wait time for the operator. For very large exports (a year of audit data on a busy site = 100k+ rows), the queued job is the only path that completes reliably.

### Synchronous path

```
GET /admin/password-policy/audit-export/export?days=30&format=csv
```

The controller fetches rows with `LIMIT 1000` and streams the CSV/JSONL content directly to the response. `Content-Type` is set to `text/csv` or `application/x-ndjson`; `Content-Disposition: attachment` triggers the browser download.

### Queued path

```
GET /admin/password-policy/audit-export/export?days=365&format=jsonl
```

The controller enqueues `AuditExportJob` (a `BaseBatchedJob`) with:

- `daysFilter` — the configured day window
- `format` — `csv` or `jsonl`
- `filesystemHandle` — the configured destination (defaults to the local runtime path)
- `requestedById` — the admin who requested the export (pinned for the download-token binding)

The job batches through the audit log via `AuditExportBatcher` (1,000 rows per batch) and streams the rows to a file on the configured filesystem. On completion, it caches a one-time-use download token + sends the requesting admin an email with the download link.

## Filesystems

The export's destination is configurable via the `auditExportFilesystem` plugin setting. Three modes:

### Local runtime (default)

Files write to `@runtime/password-policy/exports/` on the Craft host. The download token serves the file via Craft's `Response::sendFile()`.

This is the simplest setup — no filesystem provisioning needed. The drawback is that a multi-host deployment (multiple web nodes) won't share exports between nodes; the download might land on a node without the file.

For single-host deployments and dev/staging, local runtime is fine. Production multi-host deployments should configure a shared filesystem.

### Any Craft filesystem (`auditExportFilesystem = '<handle>'`)

Set the `auditExportFilesystem` setting to the handle of any configured Craft filesystem — S3, FTP, custom plugin filesystems, etc.

```php
// config/password-policy.php
return [
    'auditExportFilesystem' => 'auditExports',
];
```

Where `auditExports` is the handle of a Craft filesystem you've configured under **Settings → Filesystems**.

> 📷 *Screenshot: Filesystem configuration in Craft showing an S3 filesystem with handle "auditExports", pointing at an S3 bucket with object-lock enabled.*

The download token in this mode serves the file via the filesystem's signed-URL mechanism (S3 presigned URLs, etc.) — the file content never round-trips through Craft after the job completes.

### Disabled (`auditExportFilesystem = null`)

Setting the value to `null` (or leaving it unset) defaults to the local runtime path.

## Per-admin download tokens

Every queued export produces a one-time-use download token. The token is bound to the requesting admin — a token URL leaked or forwarded to another admin (even another admin with the same `pp:audit-export` permission) returns 403 instead of serving the file.

The mechanism:

1. The export job generates a 64-char URL-safe random token via `Craft::$app->getSecurity()->generateRandomString(64)`.
2. The token + the requesting admin's user ID + the file path are cached under `pp:audit-export-token:<token>` with a configurable TTL (default 24 hours).
3. The email contains a link to `password-policy/audit-export/download/<token>`.
4. The download controller looks up the cache entry, verifies the current user matches `requestedById`, and serves the file.
5. On successful serve, the cache entry is deleted (one-time-use).

### What happens on mismatch

- **Wrong admin** — 403 `ForbiddenHttpException`. The cache entry is **not** burned (the legitimate requester can still pull their file).
- **Expired token** — 404 `NotFoundHttpException`.
- **Already-downloaded token** — 404 `NotFoundHttpException`.
- **Token doesn't exist** — 404 `NotFoundHttpException`.

> ::: tip Token URL hygiene
> Email forwarding, shared inboxes, and email-archive systems can leak the download URL across admins. The per-admin binding closes the silent-leak risk: even if another admin clicks the URL, they can't pull the file. They get a clear 403; the audit log records the attempt; the legitimate requester can still complete their download.
> :::

## Format details

### CSV

Standard RFC 4180 quoting. UTF-8 encoded. Header row + one data row per audit log row.

| Column | Notes |
|---|---|
| `id` | Audit row ID. |
| `event` | Event type (e.g. `password_changed`). |
| `dateCreated` | UTC ISO 8601. |
| `userIdentifier` | HMAC-SHA-256 hex (64 chars). |
| `userId` | Numeric or blank if user hard-deleted. |
| `ipHash` | SHA-256 hex (64 chars) or blank. |
| `outcome` | `success`, `failure`, `denied`, `pending`. |
| `details` | JSON-encoded string (quoted/escaped per RFC 4180). |
| `previousHash` | 64-char hex. |
| `rowHash` | 64-char hex. |
| `forwardedAt` | UTC ISO 8601 or blank. |

CSVs open directly in Excel, Google Sheets, Numbers, etc.

### JSONL

One JSON object per line, separated by `\n`. Each object is the canonical JSON of an audit row (the same bytes that go into the hash chain).

```jsonl
{"event":"password_changed","dateCreated":"2026-05-15T03:33:14Z","userIdentifier":"a3f4b...","userId":42,"ipHash":"c91d7...","outcome":"success","details":{...},"previousHash":"...","rowHash":"..."}
{"event":"hibp_breach_detected","dateCreated":"2026-05-15T03:34:01Z","userIdentifier":"e7g8h...","userId":67,"ipHash":"a8b7c...","outcome":"success","details":{...},"previousHash":"...","rowHash":"..."}
```

JSONL is the idiomatic format for log-processing tools (jq, Elasticsearch bulk import, Splunk indexer, etc.):

```bash
# Count events by type
jq -r '.event' export.jsonl | sort | uniq -c | sort -rn

# Find all admin-initiated changes
jq 'select(.details.reason == "AdminChange")' export.jsonl

# Re-verify hash chain offline
jq -r '. | @json' export.jsonl | python3 verify-chain.py
```

## Email notification

When the queued export completes, the requesting admin receives an email via the `password-policy:audit-export-ready` system message:

> Subject: Your audit log export is ready
>
> Hi {admin name},
>
> Your audit log export of 47,283 rows for the date range 2026-04-15 to 2026-05-15 is ready.
>
> [Download CSV (12.4 MB)]
>
> This download link is valid for 24 hours and bound to your account.

The link expires when the cache entry expires (default 24 hours). For longer retention, configure the `auditExportFilesystem` to point at S3 with your own object-lifecycle policy — the file persists in S3 independent of the cache entry.

## Compliance evidence workflow

The audit export is the standard mechanism for assembling compliance evidence packages. Three recipes:

### Annual audit pull

A compliance auditor needs the past 12 months of audit data:

1. Open **Utilities → Audit Export**.
2. Set the date range to `Last 365 days`.
3. Format: **JSONL** (auditor can run `jq` queries + run the offline verifier).
4. Click **Run export**.
5. Job queues; admin receives the download link via email.
6. Pull the JSONL; pull the plugin source from GitHub; run the verifier against the JSONL.

### Monthly evidence snapshot

Operations team archives a monthly snapshot to S3 for retention:

1. Configure `auditExportFilesystem` to point at an S3 filesystem with Object Lock enabled.
2. Schedule a monthly cron that runs:

   ```bash
   ./craft password-policy/audit/export --from=$(date -d 'last month' +%Y-%m-01) --to=$(date -d 'today' +%Y-%m-01) --format=jsonl
   ```

3. The job writes the JSONL to S3 with the date-stamped filename. Object Lock prevents tampering after write.
4. Combined with the [verifier CLI](./audit-verifier.md), this provides external-anchoring without requiring an RFC 3161 TSA — S3 Object Lock is sufficient for most evidence-package requirements.

### Incident-response pull

A security incident requires a specific user's audit history:

1. From the CP, navigate to **Password Policy → Audit log** (the AuditLogElement index).
2. Filter by `userId` via the condition builder.
3. Use the **Export selection** element action to export just the filtered rows.
4. The action enqueues the same `AuditExportJob` scoped to the filtered IDs.
5. Email arrives with the targeted export.

## Console commands

```bash
# Synchronous export from CLI (no row-count limit — beware memory for large exports)
./craft password-policy/audit/export --from=2026-04-01 --to=2026-05-01 --format=csv > export.csv

# Queue an async export
./craft password-policy/audit/export --from=2026-01-01 --format=jsonl --async

# List recently-completed exports
./craft password-policy/audit/exports
```

The CLI variant of synchronous export streams to stdout — useful for piping into other tools without a temp file.

## Permissions

| Permission | What it grants |
|---|---|
| `pp:audit-view` | Audit log index access (read). Can't trigger exports. |
| `pp:audit-export` | Triggers the export utility, includes audit-view. Required to run the queued job from the CP. |

A typical role split:

- **Auditors** — `pp:audit-view` only. They can browse, filter, and use the verifier CLI but can't pull exports.
- **Compliance operations** — `pp:audit-view + pp:audit-export`. They pull the evidence packages.
- **DB admins** — neither permission. They have raw DB access for emergencies but no CP affordance for export.

## See also

- [Audit logging](./audit-logging.md) — the source of the rows being exported.
- [Audit verifier](./audit-verifier.md) — verify the integrity of a JSONL export offline.
- [SIEM forwarders](./siem-forwarders.md) — alternative streaming-to-SIEM model for ongoing log aggregation.
- [Webhooks](./webhooks.md) — event-by-event delivery for integrations.
- [Compliance frameworks](../operations/compliance-frameworks.md) — PCI DSS §10.5.1 12-month retention, SOC 2 evidence requirements.
