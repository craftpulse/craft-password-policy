# Phase 4 — Audit Logging Service + Craft Event Listeners

## Overview

Phase 4 adds comprehensive audit logging for password-related security events. The audit log records who, what, when, where, and outcome — without ever storing password data.

## AuditLogService

### `logEvent()`

Central logging method. Key behaviors:
- **Edition gated**: No-ops silently on Lite/Pro
- **Try/catch wrapped**: Never blocks the parent operation
- **Runtime-enforced detail allowlist**: `array_intersect_key()` strips any key not on the approved list
- **IP hashing**: Stores SHA-256 of IP, never raw
- **User identifier**: HMAC-SHA-256 of email using Craft's security key for post-deletion correlation

### Allowed Detail Keys

`deviceLabel`, `groupId`, `groupName`, `reason`, `violationType`, `source`, `outcome`, `method`, `failMode`

Any other key in the `$details` array is silently stripped.

### Query Methods

- `getEventsForUser($userId, $limit)` — User-scoped timeline
- `getRecentEvents($limit, $eventFilter)` — Global feed with optional filter
- `purgeOldEntries($daysToKeep)` — Retention cleanup

## Events Logged

| Event | When | Source |
|-------|------|--------|
| `password_changed` | After successful password save | PasswordPolicy.php EVENT_AFTER_SAVE |
| `password_reset_forced` | After force reset | RetentionService (future) |
| `hibp_breach_detected` | Password found in HIBP | PwnedValidator |
| `hibp_check_failed` | HIBP API unreachable | PwnedValidator |
| `account_locked` | Craft locks user after failed attempts | Users::EVENT_AFTER_LOCK_USER |
| `account_unlocked` | Admin unlocks user | Users::EVENT_AFTER_UNLOCK_USER |

## PwnedValidator Updates

- Now returns `null` on API failure (distinct from `false` = not breached)
- Supports fail-open (default) and fail-closed modes via `pwnedFailMode` setting
- Logs `hibp_breach_detected` and `hibp_check_failed` to audit log
- `#[SensitiveParameter]` added to `pwned()` method

## AuditController (Console)

- `password-policy/audit/purge --days=365` — Purge old entries
- `password-policy/audit/export --format=csv --days=90` — Export to stdout
- `--include-user-details` flag resolves user emails for export

## GDPR Notes

- IP addresses stored as SHA-256 hashes only
- User identifier uses HMAC-SHA-256 (key can be destroyed)
- User deletion: SET NULL preserves anonymous audit records
- Configurable retention period (default 365 days)

---

## Compliance-grade enhancements (Phase 11–12)

Added 2026-05-01 from competitive analysis of the Trails plugin. These six items elevate the Enterprise audit log from "log table" to "tamper-evident audit trail with auditor-runnable verification" — the difference matters for NIS2, SOC 2, ISO 27001, and PCI-DSS evidence packages. See `PLAN.md` Phase 11/12 rows for build sequencing.

### (a) Hash-chained audit rows — Phase 11

Each row stores the SHA-256 hash of `(canonical JSON of this row) + (previousHash)`, forming an append-only chain. Schema additions to `passwordpolicy_audit_log`:

- `rowHash` — `CHAR(64) NOT NULL` — sha256 hex of `canonicalJson(row) + previousHash`
- `previousHash` — `CHAR(64) NOT NULL` — `rowHash` of the immediately preceding row (`'0' x 64` for genesis row)

Canonical JSON serialises in a fixed key order (alphabetical) so the hash is reproducible. The `id` column is **excluded** from the hash payload (auto-increment isn't deterministic across restores) — the chain order is established by `dateCreated` + insertion order.

No Merkle batching needed at password-event volume (~10–100 events/day for typical Enterprise installs). A flat per-row chain is sufficient and simpler to verify.

`AuditLogService::logEvent()` becomes responsible for:
1. Loading the latest row's `rowHash` (single indexed query)
2. Computing the new row's `rowHash`
3. Inserting inside a transaction with `SELECT ... FOR UPDATE` on the latest row to prevent concurrent insert races

**Auditor pitch:** "Every row in our audit log cryptographically chains to the previous row. Tampering with any historical entry breaks the chain at that point and is detected by the verifier."

### (b) Independent verifier CLI — Phase 11

New console command: `password-policy/audit/verify [--from=<date>] [--to=<date>]`.

Walks the chain in insertion order, recomputes `rowHash` for each row, compares to the stored value. On the first mismatch, prints the offending row's id + dateCreated + computed hash + stored hash, exits with `ExitCode::DATAERR`. On clean pass, prints `OK: N rows verified` and exits `ExitCode::OK`.

The verifier code path must be **open-source** (live in the public repo, not behind any paywall) so auditors can read it and run it independently. This is the credibility multiplier on (a) — a hash chain with no public verifier is just marketing.

**Auditor pitch:** "Run `php craft password-policy/audit/verify` yourself. The verifier is in our public repo. If it returns OK, the audit log is intact."

### (c) Field-level before/after diffs on policy changes — Phase 11

When an admin saves a Pro named policy, the audit row's `details` JSON includes a structured diff:

```json
{
    "policyId": 4,
    "policyName": "Editors",
    "diff": {
        "minLength": {"old": 8, "new": 12},
        "enableHibp": {"old": false, "new": true},
        "groupIds": {"old": [3, 5], "new": [3, 5, 7]}
    }
}
```

Diff is computed in `PolicyService::beforeSavePolicy()` by comparing the loaded record against the request payload, captured into the audit context, and emitted on `policy_changed` event after successful save. Unchanged fields are omitted. Boolean tri-state and array-valued fields use the same shape.

**Maps to:** ISO 27002:2022 A.5.37 (documented operating procedures), SOC 2 CC8.1 (change management evidence), NIS2 Article 21(2)(e) (basic cyber hygiene practices).

New event type added to the table above:

| `policy_changed` | After Pro named-policy save | PolicyService::EVENT_AFTER_SAVE_POLICY |

### (d) Explicit PII allowlist registered per event type — Phase 11

Today the allowlist (`deviceLabel, groupId, groupName, reason, violationType, source, outcome, method, failMode`) is a single global list applied via `array_intersect_key()`. For Enterprise compliance evidence, codify it as a **per-event-class registration** so each event type declares exactly what details it's permitted to log:

```php
final class AuditLogService
{
    private const ALLOWED_DETAILS = [
        'password_changed' => ['source', 'method', 'reason'],
        'hibp_breach_detected' => ['source', 'failMode'],
        'policy_changed' => ['policyId', 'policyName', 'diff'],
        // ...one entry per event type
    ];
}
```

Behaviour:
- **Fail closed** — an event type not in the registry is rejected (logs a warning + drops the audit row, never silently allows arbitrary keys through)
- **Inspectable** — exposed via a CP utility ("Audit Log Schema") and a console command `password-policy/audit/schema` so auditors can read the full per-event allowlist as static evidence
- **Test-enforced** — Pest fixture verifies every fired event class has a registry entry

**Why:** "We never log PII" is a claim. "Here's the per-event allowlist, here's the test that fails if you add a new event without declaring its allowlist, here's the verifier that drops anything unrecognised" is evidence. Same shift as (a)/(b).

### (e) `AlertCooldownService` — Phase 12

Generalised cooldown/dedup for alert emails. Pattern lives next to `NotificationService`, reuses the `passwordpolicy_notification_log` table or adds a parallel `passwordpolicy_alert_cooldown` table (decision deferred to Phase 12 implementation).

Public API:

```php
$alertCooldown->shouldSend(string $alertKey, string $scope, int $cooldownSeconds): bool;
$alertCooldown->markSent(string $alertKey, string $scope): void;
```

`scope` is a free-form discriminator (`"user:123"`, `"group:5"`, `"global"`) so the same alert key can have independent cooldowns per affected entity.

**Use cases registered in Phase 12:**
- HIBP-on-login mass detection (credential stuffing pattern) — global scope, 1h cooldown
- Group-deletion cascade alerts — per-group scope, no cooldown (rare event)
- Force-reset bursts — global scope, 15min cooldown

Without this, P1.13 + Phase 11 alerts each reinvent throttling and we end up with three slightly different dedup mechanisms. Service-ify it once.

### (f) Streaming audit-log exports — Phase 12

Extend `AuditController::actionExport` to defer to a queue job for any export with `--days > 30` or no date filter. New job: `ExportAuditLogJob extends BaseBatchedJob`, mirrors P1.4's `SendPasswordExpiryRemindersJob` pattern.

- `batchSize: 1000` rows
- Streams to a temporary file in `storage/runtime/password-policy/exports/<uid>.csv`
- On completion, fires `AuditExportCompleteEvent` — admins can hook to upload to S3, attach to a ticket, etc.
- Email notification to the requesting admin with a one-time download link (Pro: in-CP delivery; Enterprise extends with signed-URL S3 delivery in a future phase)

**Why:** Audit log exports for SOC 2 / NIS2 evidence packages routinely cover 12+ months on busy installs. PHP memory ceilings make synchronous CSV generation fragile at that volume.

### Items deliberately not adopted from Trails

- **RFC 3161 external timestamping** — overkill for password-event volume. Hash-chain + independent verifier covers the same auditor question (tamper evidence). RFC 3161 belongs in a future standalone audit-log plugin if/when that ships.
- **AWS S3 Object Lock anchoring** — same rationale as above.
- **GeoIP enrichment on audit rows** — outside Password Policy's lane (would belong in a separate device/anomaly plugin).
- **Splunk HEC / Datadog destinations** — already in Phase 12's SIEM scope, not a Trails-derived addition.
