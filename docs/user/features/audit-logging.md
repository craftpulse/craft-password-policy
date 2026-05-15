# Audit Logging

The Enterprise edition ships a tamper-evident audit log that records every password-related security event in your Craft install. It's hash-chained from the row level up, verifiable end-to-end by a bundled console command, and built privacy-first — no raw IPs, no plaintext emails, no PII outside a fail-closed per-event allowlist.

> 📷 *Screenshot: The Audit Log element index in the control panel, with the status pill column showing successful and failed events, and the inline detail panel for a selected row.*

This page covers what the audit log captures, the schema, the privacy guarantees, the hash chain mechanics, and the verifier CLI. For the visible Enterprise UI on top of this infrastructure, see [Compliance Dashboard](./compliance-dashboard.md). For SIEM and webhook integration, see [SIEM forwarders](./siem-forwarders.md) and [Webhooks](./webhooks.md).

## What's captured

| Event | When it fires | Source |
|---|---|---|
| `password_changed` | After a successful password save | `User::EVENT_AFTER_SAVE` |
| `password_reset_forced` | An admin or automation forces a reset | `UserStateService` |
| `account_locked` | Craft locks a user after failed attempts | `Users::EVENT_AFTER_LOCK_USER` |
| `account_unlocked` | An admin unlocks a user | `Users::EVENT_AFTER_UNLOCK_USER` |
| `hibp_breach_detected` | A user's password is found in the HIBP breach database (change-time or login) | `PasswordService` |
| `hibp_check_failed` | The HIBP API is unreachable | `PasswordService` |
| `policy_changed` | A Pro named policy is saved (Enterprise captures the field-level diff) | `PolicyService::EVENT_AFTER_SAVE_POLICY` |
| `chain_rotated` | An admin-initiated audit-chain rotation event (rare) | `AuditLogService` |
| `audit_export_completed` | A queued audit export finishes | `AuditExportJob` |
| `alert_cooldown_fired` | An alert was suppressed by the cooldown service | `AlertCooldownService` |
| `siem_forward_attempted` | A row was forwarded (or failed) to a SIEM endpoint | `SiemForwardJob` |
| `webhook_delivery_attempted` | A webhook was delivered (or failed) | `WebhookForwardJob` |

Every event is captured on every edition. Edition gating applies to **exposure** — the CP audit-log index, the verifier CLI, the dashboard, the forwarders, the export utility all require Enterprise. The underlying capture happens whether or not you have Enterprise installed, so upgrading a site from Pro to Enterprise mid-life surfaces the audit history you already had.

## Schema

The `passwordpolicy_audit_log` table backs the `AuditLogElement` Craft element. Each row stores:

| Column | Type | Purpose |
|---|---|---|
| `id` | int (FK to `craft_elements.id`) | Element identity. |
| `event` | string(64) | One of the event types above. |
| `userIdentifier` | string(64) | HMAC-SHA-256 of the affected user's email, keyed by `CRAFT_AUDIT_PII_KEY`. See [Privacy guarantees](#privacy-guarantees). |
| `userId` | int, nullable | FK to `craft_users.id` (`SET NULL` on user hard-delete). |
| `ipHash` | string(64), nullable | SHA-256 of the request IP. Never raw. |
| `outcome` | enum | `success`, `failure`, `denied`, `pending`. |
| `details` | JSON | Per-event structured fields (allowlisted; see below). |
| `previousHash` | char(64) | `rowHash` of the immediately preceding row (`'0' × 64` for the genesis row). |
| `rowHash` | char(64) | SHA-256 of the canonical JSON of this row plus `previousHash`. |
| `forwardedAt` | datetime, nullable | Set by the SIEM forwarder when this row has been delivered. `NULL` means unforwarded. |
| `forwardAttempts` | int | Retry counter for the SIEM forwarder. |
| `dateCreated`, `dateUpdated`, `uid` | standard Craft columns | |

The table grows append-only — `AuditLogElement::canSave()` returns `false` after the initial insert, so rows cannot be edited in place. Retention purges hard-delete rows that fall outside the configured window (see [Retention](#retention)).

## Privacy guarantees

The audit log was designed so that a copy of the table — leaked, shared with an auditor, or exported to a SIEM — does not double as a user-tracking dataset.

### HMAC-hashed `userIdentifier`

The `userIdentifier` column stores `hash_hmac('sha256', $email, $auditPiiKey)`. A row carries no email address. An auditor who already knows a target user's email can re-hash with the same key and find their rows; an attacker with table read access cannot enumerate emails from the column.

The key is `CRAFT_AUDIT_PII_KEY` — an env var **independent of Craft's `securityKey`**. Rotating it destroys historical correlation against newly-written rows without breaking sessions, CSRF tokens, asset URLs, or anything else `securityKey` anchors. See [Provisioning `CRAFT_AUDIT_PII_KEY`](#provisioning-the-pii-key) below for the one-shot setup.

### SHA-256-hashed `ipHash`

The `ipHash` column stores `hash('sha256', $request->getRemoteIP())`. Raw IPs never reach the database. Two requests from the same IP produce the same hash; an auditor investigating a single-IP attack pattern can correlate within the dataset without seeing the IP itself.

### User-Agent is dropped

Browser and OS fingerprints don't enter the audit row. The plugin's parallel new-device-alert notification captures a redacted `deviceLabel` (e.g. `"Chrome on macOS"`) — that's the operational-visibility surface, not the audit log.

### Per-event PII allowlist (G5)

The `details` JSON column is filtered against a per-event allowlist before write. `AuditLogService::logEvent()` runs every payload through:

```php
$details = array_intersect_key($details, self::ALLOWED_DETAILS_BY_EVENT[$event] ?? []);
```

An event type not in `ALLOWED_DETAILS_BY_EVENT` is **fail-closed**: the row is dropped and a warning logged. Adding a new event type without declaring its allowlist is a static defect — the test suite has an assertion that fails if any fired event class lacks a registry entry.

Inspect the live allowlist via the **Audit Log Schema** utility (`Utilities → Audit Log Schema`) or the console command:

```bash
./craft password-policy/audit/schema
```

Both surface the same `event → allowed-keys` mapping as static evidence for auditors.

## Hash chain (G1)

Every row stores the SHA-256 of its canonical JSON plus the previous row's `rowHash`. Tampering with any historical row breaks the chain at that point — detectable by the [verifier](#verifier-cli).

### Canonical payload

`AuditLogService::canonicalize($row)` produces deterministic bytes:

- Keys serialised in alphabetical order.
- Datetimes formatted as `Y-m-d\TH:i:s\Z` (UTC, no microseconds).
- `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` flags applied.
- Null values preserved (not stripped).
- The `id` column **excluded** — auto-increment isn't deterministic across database restores. Chain order is established by `dateCreated` + insertion order.
- The `rowHash` and `previousHash` columns themselves excluded from the canonical payload (they're outputs of the hash, not inputs).

### Genesis row

The first row in the table uses `previousHash = '0' × 64` (sixty-four zeros). `AuditLogService::GENESIS_PREVIOUS_HASH` is the canonical source — both the writer and the verifier reference it.

### Write transaction

`AuditLogService::logEvent()` runs inside a database transaction:

1. `SELECT ... FOR UPDATE` on the latest row's `rowHash` (single indexed query).
2. Compute the new row's `rowHash` from the canonical payload + the latest hash.
3. Insert.

The `FOR UPDATE` row lock prevents concurrent writers from chaining off the same `previousHash` (which would fork the chain at that point).

### Privacy + chain interaction

The `userIdentifier` column is part of the canonical payload. Rotating `CRAFT_AUDIT_PII_KEY` does **not** invalidate the chain for existing rows — those rows still carry the hash they were written with, and the verifier reads them as-is. Rotation affects future writes; it doesn't rewrite history.

> ::: warning Don't log the canonical payload
> Logging `AuditLogService::canonicalize($row)` at debug level would compromise the chain's tamper-detection property — an attacker reading logs could reconstruct the canonical string and forge matching rows. The plugin never logs the canonical payload. Don't add a `Craft::debug()` call on it.
> :::

## Verifier CLI (G2)

Run from your Craft project root:

```bash
./craft password-policy/audit/verify
```

The verifier walks the chain row-by-row, recomputes each `rowHash` from the stored payload, and compares against the stored value. It reads raw `Query` cursors — not Craft element queries — so retention-purge artifacts and element soft-delete states don't trip it up.

### Output

On a clean pass:

```
OK: 12347 rows verified.
```

Exit code `0`.

On a chain break:

```
FAILED at row id=8821 (dateCreated 2026-04-12T09:33:14Z)
    stored rowHash:   8e3a4f2d…
    computed rowHash: c91d7a8b…
    previous rowHash matched: yes
```

Exit code `1`. The verifier stops at the first break — re-run with `--from=<date>` after fixing or investigating to verify the rest of the chain.

On an unreadable row (malformed JSON, missing column, etc.):

Exit code `2`.

### Flags

| Flag | Purpose |
|---|---|
| `--from=<date>` | Start verification from this date. Useful for daily verification crons that only check yesterday's writes. |
| `--to=<date>` | Stop verification at this date. |
| `--json` | Emit machine-readable JSON output instead of the human-readable report. Designed for CI / monitoring integration. |

### Cron recipe

Add a daily verifier run to your production cron:

```cron
# Verify yesterday's audit chain every morning at 03:00
0 3 * * * cd /path/to/project && ./craft password-policy/audit/verify --from=$(date -d yesterday +%Y-%m-%d) --to=$(date -d yesterday +%Y-%m-%d) --json
```

Pipe the JSON output to your monitoring stack. A non-zero exit code is an alertable event — chain integrity has been compromised either by tampering or by a disk error.

### Auditor usage

The verifier source lives in `src/console/controllers/AuditController.php` and is part of the plugin's public GitHub repository. An auditor can clone the repo, run `composer install`, point the config at your database, and run the verifier from a fresh checkout — independent of your running Craft install. This is the credibility multiplier on the hash chain: a hash chain with no public verifier is just marketing; the verifier turns it into evidence.

Permission `pp:audit-verify` is required to run the command from a CP-authenticated console; the same command also runs without a CP user identity for the auditor-from-fresh-checkout case.

## Policy change diffs (G4)

When an admin saves a Pro named policy, the audit row's `details.diff` captures a field-level before/after:

```json
{
    "policyId": 4,
    "policyName": "Editors",
    "diff": {
        "minLength": {"old": 8, "new": 12},
        "hibp": {"old": false, "new": true},
        "groupIds": {"old": [3, 5], "new": [3, 5, 7]}
    }
}
```

Unchanged fields are omitted. Boolean tri-state and array-valued fields use the same shape. The diff is computed in `PolicyService::beforeSavePolicy()` by comparing the loaded record against the request payload, captured into the audit context, and emitted on the `policy_changed` event after a successful save.

This is the literal change-management evidence compliance buyers want: every policy modification is captured with what changed, who changed it, and when — not just "something was edited."

## Retention

The audit log is retention-managed. Configure the window in **Settings → Password Policy → Audit → Audit log retention days** (default `365`). The `password-policy/gc/run` console command hard-deletes rows older than the configured window.

```cron
# Run retention nightly at 02:00
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run
```

> ::: warning Retention is a hard delete
> The audit log is append-only for write but retention is a hard delete (via `craft_elements` `DELETE` + FK CASCADE on `passwordpolicy_audit_log`). Soft-delete via `dateDeleted` is not used — compliance frameworks require that retention windows actually remove the data, not just hide it. The verifier CLI tolerates this: it walks the surviving rows and verifies the chain among them.
> :::

Default retention satisfies PCI DSS v4.0.1 §10.5.1 (≥12 months of audit logs). For longer retention requirements, increase the setting and provision additional database storage.

## Provisioning the PII key

Generate the audit-PII key on first install:

```bash
./craft password-policy/audit/generate-pii-key
```

The command:

- Generates 32 cryptographically-random bytes (64 hex chars — the same shape as Craft's `securityKey`).
- Writes `CRAFT_AUDIT_PII_KEY` to your local `.env` file.
- Prints the key so you can copy it to your production environment.

The default `config/password-policy.php` reads the env var:

```php
<?php

use craft\helpers\App;

return [
    'auditPiiKey' => App::env('CRAFT_AUDIT_PII_KEY'),
];
```

Set the same env var on every environment that runs the plugin — local, staging, production, CI for tests that touch audit-log rows. Rows hashed in one environment with a different key are not correlatable from another.

### Rotating the key

```bash
./craft password-policy/audit/generate-pii-key --force
```

The `--force` flag is required to overwrite an existing key. Without it, the command refuses (accidental rotation orphans historical correlation).

After rotation:

- New audit rows hash `userIdentifier` with the new key.
- Existing audit rows still carry hashes from the previous key. Those rows remain correlatable only by an auditor who retains the previous key value.
- The verifier CLI continues to verify the chain integrity unchanged — `userIdentifier` is part of the canonical payload, so rotating the key for new rows does not break the chain of existing rows. Rotation affects PII correlation only.

### When the key is unset

If `CRAFT_AUDIT_PII_KEY` is unset, the plugin falls back to Craft's `securityKey` for HMAC. This is for dev-install convenience — fresh installs still produce hashable rows without the env var. **The privacy property (rotation without site breakage) only applies once you've run the generator and deployed the env var.** Production deployments should always set it explicitly.

## HIBP-on-login

HIBP-on-login is a Pro feature that re-checks every signing-in user's password against the Have I Been Pwned breach database via the same k-anonymity protocol used at password-change time. The listener at `User::EVENT_BEFORE_AUTHENTICATE` is the only Craft 5 hook with synchronous plaintext-in-scope access during login. On a match the plugin:

1. Sets `passwordResetRequired = true` on the user (saved with `muteEvents` to avoid recursion).
2. Sends a `breach-detected` notification email.
3. Fires `BreachDetectedEvent` for consumer hooks.
4. Writes an audit-log entry (`hibp_breach_detected`) on Enterprise + audit-toggle.

**The login is never blocked.** The user can sign in; they're prompted to change their password on the same session.

### Privacy invariant

The listener never logs the plaintext password, the full SHA-1 hash, or the bucket suffix. Only the 5-char k-anonymity prefix and a "match found" boolean ever leave the listener. The dedup cache key uses `userId` only — embedding the SHA-1 prefix in an inspectable cache key would reconstruct the linkability property k-anonymity is designed to eliminate.

### Failure modes

| Condition | Behaviour | Log level |
|---|---|---|
| API reachable, no breach found | Silent | — |
| API reachable, breach found | Above flow runs | INFO |
| API unreachable (timeout, 5xx) | Fail open (login proceeds) | WARNING |
| API rate-limited (429) | Site-wide backoff cache key set; every caller short-circuits until the backoff expires | WARNING |
| TLS verification failure | Fail open | WARNING |

## Compliance framework anchors

These citations are anchors for an operator's evidence package — not certifications. The plugin provides specific technical measures that controllers can rely on as part of their framework obligations.

| Framework | Clauses the audit log addresses |
|---|---|
| **NIS2** | Article 21(2)(g) basic cyber hygiene practices; Article 21(2)(i) human resources security, access control, asset management. (Not 21(2)(j) — that's MFA, which is Craft core's territory.) |
| **SOC 2** | CC6.1 logical access security; CC6.3 access provisioning/de-provisioning; CC7.2 system monitoring + anomaly detection; CC8.1 change management evidence (policy change diffs). |
| **ISO 27001:2022 / 27002:2022** | A.5.15 access control; A.5.17 authentication information; A.5.33 protection of records (direct map for hash chain); A.8.5 secure authentication; A.8.15 logging; A.8.16 monitoring activities. |
| **PCI DSS v4.0.1** | §10.2 audit log content requirements; §10.3 audit logs protected from destruction (hash chain); §10.5.1 retention (≥12 months; default 365 days satisfies); §8.3.4 lockout (delegated to Craft core); §8.3.5 breach-driven change (HIBP-on-login). |
| **GDPR** | Article 5(1)(f) integrity and confidentiality; Article 17 right to erasure (`SET NULL` on user hard-delete + HMAC userIdentifier preserves audit trail without retaining the email); Article 25 data protection by design and by default; Article 32(1)(b) ongoing confidentiality/integrity/availability; Article 32(1)(d) regular testing (the verifier CLI). |

For the full framework-by-framework mapping including all Pro+Enterprise features, see [Compliance frameworks](../operations/compliance-frameworks.md).

## Hooking into events

The plugin fires structured events for every audit write. Listen for them to mirror the audit trail into your own systems.

```php
use craftpulse\passwordpolicy\events\AuditChainRotatedEvent;
use craftpulse\passwordpolicy\services\AuditLogService;
use yii\base\Event;

Event::on(
    AuditLogService::class,
    AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
    function(AuditChainRotatedEvent $event) {
        // Notify the on-call channel; the audit chain has been administratively rotated.
    }
);
```

See [Events reference](../reference/events.md) for the full catalog with payload tables.

## See also

- [Audit verifier CLI](./audit-verifier.md) — deeper detail on the verifier, including the auditor-from-fresh-checkout workflow.
- [Compliance Dashboard](./compliance-dashboard.md) — the Enterprise UI on top of the audit log.
- [SIEM forwarders](./siem-forwarders.md) — Syslog-over-TLS to Splunk HEC, Datadog Logs, and any RFC 5424 receiver.
- [Webhooks](./webhooks.md) — HMAC-signed delivery for consumer integrations.
- [Audit export](./audit-export.md) — Streaming CSV/JSONL export with per-admin download tokens.
- [Compliance frameworks](../operations/compliance-frameworks.md) — Per-clause mapping for evidence packages.
