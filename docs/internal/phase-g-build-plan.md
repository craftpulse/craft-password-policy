---
title: Phase G Build Plan — Enterprise (Compliance + Audit Integrity + SIEM)
version: 5.2.0
phase: G
features: [hash-chained-audit, verifier-cli, compliance-dashboard, policy-change-diffs, pii-allowlist, custom-blocklist, alert-cooldown, siem-syslog, webhook-full, audit-export, custom-template-paths, enterprise-notif-keys]
build_order: [G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11, G12]
estimated_effort: ~6-8 working days for the 5.2.0 subset; G3 compliance dashboard + G9 webhook full surface (infrastructure + management UI + endpoint CRUD) are the two largest single features
deferred_to_5_3: [ApiTokenService + ApiController REST surface (Phase 12 § REST)]
not_adopted: [syslog UDP forwarder protocol — UDP unreliable for audit forwarding, TCP/TLS is the compliance-correct default; no buyer profile asks for it. Cut from the matrix, not parked.]
last_updated: 2026-05-06
user_confirmation: 2026-05-06 — user confirmed deferral scope (G9 ships whole; Phase 12 REST defers; syslog UDP dropped, not parked)
---

# Phase G — Enterprise (Compliance + Audit Integrity + SIEM)

Layered build plan for Phase G — the Enterprise edition of v5.2.0. Locks the architectural decisions enumerated in `plan.md` § 3 P3 (Phase 11 a/b/c/d, Phase 12 e/f) plus the two Phase G additions (per-policy custom blocklist, custom email template paths, Enterprise notification keys).

This is the build brief for whoever runs Phase G (likely `craft-feature-builder`). Read it whole before starting. Do not relitigate locked architecture — push back on me, not the spec. If a verify gate fails and you cannot recover, STOP and report; do not push past failures.

---

## Context

- Plugin: `/Users/michtio/dev/craft-plugins/v5/craft-password-policy`
- Playground: `/Users/michtio/dev/craft-plugin-playground/cms_v5` (URL `https://plugin-playground-v5.ddev.site/admin`, login `development@craftpulse.com` / `Letmein-Craftpulse1!`)
- Branch: `5.x` (currently 69+ commits ahead of `origin/5.x`, working tree clean modulo this plan + the F2 + F UI sweep changes already committed)
- Plugin edition during build: switch playground to **Enterprise** for Phase G work — Pro stays the default for parts of the build that need to verify the strip-on-save defense.
- Mailpit: `ddev describe` shows the URL.
- Suite at start of Phase G: **551 passing / 0 skipped / 1151 assertions**. ECS clean, PHPStan clean (3-entry baseline unchanged).

Memory store: `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md`. Read first. Especially:

- `project_audit_capture_principle.md` — capture on every edition; gate exposure not capture. Phase G writes the chain on every edition (Lite included). Edition gates apply to the verifier UI surfaces, the SIEM forwarders, the webhook delivery, the dashboard, the export — never the chain itself.
- `project_security_usps.md` — privacy-by-design (HMAC userIdentifier, SHA-256 ipHash, no UA storage). Phase G must not regress these.
- `project_compliance_positioning.md` — NIS2 / NIST 800-63B / PCI-DSS / GDPR are the load-bearing buyer story. Audit chain + verifier CLI + per-event PII allowlist are the literal evidence package.
- `project_competitive_landscape.md` — Trails is the audit-log differentiator pivot point. Hash chain + auditor-runnable verifier + per-event PII allowlist + password-event-scoped HMAC is the lane Trails doesn't occupy.
- `feedback_use_migrate_create.md` — every migration via `ddev craft migrate/create <Name> --plugin=password-policy`. **Never hand-pick filenames.**
- `feedback_native_callout_components.md` — `<blockquote class="note tip|warning">` for callouts; `|datetime`/`|time` for locale-aware timestamps. Compliance Dashboard's "last verifier run" / "rows pending forwarding" callouts use these.
- `feedback_craft5_json_content_pattern.md` — per-(entity, site) editable content via JSON `content` column. G11 custom template paths extend the existing `passwordpolicy_notification_templates` JSON content shape (no new column on the table).
- `feedback_editable_table_default.md` — default to `forms.editableTableField` for admin-managed lists. G6 per-policy custom blocklist editor reuses the existing P1.11 EditableTable surface, scoped to the policy.

Project guide: `CLAUDE.md` + `.claude/rules/*.md`. Especially `coding-style.md` (PHPDoc + section header non-negotiables), `architecture.md` (layering rules — services own logic, controllers wire HTTP, models own validation), `security.md` (sensitive-key strip + `#[\SensitiveParameter]` + privacy comments at security listeners), `migrations.md` (idempotent guards, project-config `muteEvents`, bcrypt seed loop log toggle).

Reading order before starting:
1. `internal/plan.md` § 1 status, § 3 backlog (P3 rows for Phase 10, 11, 12 + Phase G additions), § 4 build order.
2. `internal/handover.md` § "What to build first" → Phase F → P2.8.
3. `user/features/audit-logging.md` — sections (a) – (f) under "Compliance-grade enhancements." Decisions in those sections are locked; this plan extends them with implementation-level architecture, not new features.
4. `user/reference/events.md` — current event catalog. Phase G adds five new events documented at the end of this plan.
5. `internal/history/phase-c2-build-plan.md` — structural template only. Don't relitigate Phase C2 decisions.

---

## Locked architecture (do not relitigate)

### 1. Hash-chained audit row format

Every row in `passwordpolicy_audit_log` becomes part of a SHA-256 forward chain. Schema additions:

- `rowHash` — `CHAR(64) NOT NULL` — SHA-256 hex of `canonicalJson(payload) + previousHash`.
- `previousHash` — `CHAR(64) NOT NULL` — `rowHash` of the row immediately preceding this one in `dateCreated, id` order.

**Hash algorithm:** `hash('sha256', $payload . $previousHash)`. Hex output, lowercase. No Merkle tree, no per-batch root, no RFC 3161 timestamping (rejected in `audit-logging.md`). Password-event volume (10–100 rows/day on a typical Enterprise install) does not justify any of those.

**Canonical JSON shape** — `AuditLogService::canonicalize(array $row): string`:

- Key order: alphabetical, recursively (nested arrays included).
- Whitespace: none. JSON encode flags: `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`.
- `null` values: emitted as JSON `null` (not stripped) — verifier must produce bit-identical output.
- Booleans: `true` / `false` (not coerced to `1` / `0`).
- Integers: bare numerics. No quoting.
- Strings: JSON-escaped per the flags above.

**Fields included in the canonical payload:**

- `userId`, `changedByUserId`, `event`, `outcome`, `source`, `details` (the already-allowlist-filtered JSON object), `ipHash`, `userIdentifier`, `dateCreated`, `uid`.

**Fields excluded:** `id` (auto-increment, not deterministic across restores), `rowHash` itself (would self-reference), `previousHash` (concatenated separately, not inside the payload).

**`dateCreated` format in the canonical shape:** UTC, ISO 8601 with explicit `Z` suffix — `Y-m-d\TH:i:s\Z`. Sub-second precision dropped; we get exactly that resolution out of MySQL's `DATETIME` column anyway. Document this string format explicitly in `AuditLogService::canonicalize()` — the verifier produces bit-identical output only when the format matches exactly.

**First-row contract:** `previousHash` for the genesis row is `'0' x 64` (sixty-four zeros), not NULL. NOT NULL on the column simplifies the chain-walk verifier (no null-handling branch).

**Hash computation point:** BEFORE insert. Inside a transaction with `SELECT ... FOR UPDATE` on the latest row's `rowHash` to prevent concurrent insert races.

```php
$db->transaction(function () use (...) {
    $previousHash = (new Query())
        ->select(['rowHash'])
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->forUpdate()
        ->scalar() ?? str_repeat('0', 64);

    $payload = self::canonicalize([...]);
    $rowHash = hash('sha256', $payload . $previousHash);

    $record->rowHash = $rowHash;
    $record->previousHash = $previousHash;
    $record->save(false);
});
```

**Capture is universal.** The chain runs on Lite. Lite installs that never expose audit data still write the chain — capture-on-every-edition. Edition gates apply to the verifier CLI's CP utility surface, the dashboard, the SIEM, the webhooks, the export. Not the underlying writes.

### 2. Independent verifier CLI

New console action: `password-policy/audit/verify`.

**Exit codes:**

- `0` — chain valid, full or partial-with-acceptable-boundary (see retention semantics below).
- `1` — chain break detected. Stdout/stderr names the offending row id, dateCreated, computed hash, stored hash. Verifier exits at the first break (does not continue past it).
- `2` — unreadable / schema drift / DB connect failure / malformed canonical JSON. Distinct from `1` so CI can decide whether to fail loud (likely on `1`) vs alert ops (likely on `2`).

**Output format:** human-readable by default. `--json` flag emits one JSON object per row checked (or a single summary object on clean pass) — easier for downstream tooling.

**Flags:**

- `--from <id>` — start verification at row id. `previousHash` of that row is treated as the chain-start sentinel for partial verification (see retention semantics).
- `--to <id>` — stop verification at row id (inclusive).
- `--json` — JSON output mode.
- `--quiet` — suppress per-row `OK` lines on a clean pass; only the summary line emits.

**Retention-purged-row tolerance.** The auto-prune (`AuditLogService::purgeOldEntries()`) deletes rows older than `auditLogRetentionDays`. After a prune, the first surviving row's `previousHash` legitimately references a now-deleted row. The verifier accepts this as a "chain start" boundary if and only if:

- `--from` is unset (full verification mode), AND
- The first surviving row's `dateCreated` is older than the configured retention window minus a safety margin (24h).

Otherwise — first row's `dateCreated` is recent and `previousHash` doesn't link to anything — that's a chain break, exit 1. Document the safety-margin rationale in code: it tolerates clock drift between the prune-cron host and the verifier host but doesn't paper over actual tampering.

**Permission gating.** New permission `pp:audit-verify`. Auditor-grantable without full admin. Console action checks the permission only if `$controller->user` is set (CP user invoking via web, theoretical future case); console-direct invocation bypasses the permission check (operators with shell access have already passed any meaningful gate).

**Open-source mandate.** Verifier code lives in the public repo, fully readable. Not behind any paywall, license check, or build artifact. The credibility multiplier on the chain is precisely that auditors can read and run the verifier. Add a comment block at the top of `AuditController::actionVerify` calling this out so future maintainers don't gate it.

### 3. SIEM forwarders

Protocols supported in 5.2.0: **syslog over TLS only.** UDP is dropped from the matrix entirely (not parked, not deferred — cut). UDP is unreliable for audit forwarding; the regulated-industry buyer profile this plugin targets needs delivery guarantees. Plain TCP without TLS is rare in that profile too — TLS is the compliance-correct default.

HTTP webhook forwarder ships as a full feature in G9 (infrastructure + management UI + endpoint CRUD). User-confirmed scope on 2026-05-06.

**Queue-driven via `\craft\queue\BaseBatchedJob`.** New `SiemForwardJob` follows the P1.4 `SendPasswordExpiryRemindersJob` template:

- `batchSize: 100`
- `getTtr(): 300`
- `canRetry($attempt, $error): bool { return $attempt < 5; }`
- Per-row soft-fail in `processItem` — one failed forward doesn't poison the batch.
- `loadData()` returns a `UnforwardedAuditRowBatcher` (campaign-style — re-queries each batch slice to preserve idempotency on retry).

**Per-event-class allowlist.** New setting `siemForwardEventClasses: array<string>` (default `['audit_log']`). Operators who want SIEM coverage of notification activity opt in via `['audit_log', 'notification_log']`. The allowlist is the gate — schema is unchanged on `notification_log`, but the forwarder reads from a join across both tables when the allowlist permits.

This implements `project_audit_capture_principle.md`: capture is universal (we always write `notification_log` rows on every edition); exposure is gated (only Enterprise installs even register the forwarder).

**Circuit breaker per forwarder.** Cache key `pp:siem-forwarder-circuit:{forwarderId}`, value tracks consecutive failure count. Opens at 5 consecutive failures (default; configurable per-forwarder), half-opens on a probe job after a configurable cooldown (default 5 minutes). Reuse the cache idiom from HIBP 429 backoff — same fail-loud-on-429-then-back-off pattern.

**Failure mode.** Forwarder failures NEVER block the originating audit/notification write. The forwarder is read-side only. A row is forwardable if `forwardedAt IS NULL` on the audit row (new column, see G8 schema). Successful forward writes `forwardedAt = NOW()`. Failed forwards leave the column null and increment a separate `forwardAttempts` counter (clamped at INT_MAX; never causes the row's hash to recompute — the chain payload excludes both columns).

**`SiemForwarderRecord` schema (G8):**

- `id` (primary key)
- `name` (admin-supplied display label, nullable)
- `protocol` (enum: `syslog-tls`; webhook protocol joins in 5.3)
- `host`, `port`
- `tlsCertVerify` (bool, default true — operators with self-signed CA chains use `App::parseEnv` indirection for the CA bundle path on a separate field)
- `tlsCaBundlePath` (nullable, env-var-resolved at use)
- `eventClasses` (JSON array — overrides the global `siemForwardEventClasses` setting per-forwarder when set)
- `enabled` (bool)
- `circuitOpenAt` (datetime nullable — last cooldown-window reset)
- `consecutiveFailures` (int)
- `dateCreated`, `dateUpdated`, `uid`

### 4. Webhook HMAC scheme

Locked. G9 ships in full in 5.2.0: infrastructure + CP management UI + endpoint CRUD.

- **Signature header:** `X-PasswordPolicy-Signature: sha256=<hex>`. Industry-standard format; matches Stripe and GitHub conventions.
- **Payload canonicalisation:** raw request body bytes — no key reordering, no whitespace normalisation. Recipients verify against the bytes they received. The body is whatever JSON we serialised on send; consumer treats it as opaque bytes.
- **Timestamp header:** `X-PasswordPolicy-Timestamp: <unix-epoch-seconds>`. Recipient rejects if `|now - timestamp| > 300` (5 minutes). Document this constraint in the consumer-facing webhook docs.
- **Idempotency key:** `X-PasswordPolicy-Event-Id: <uuid>`. Consumer uses this to dedup replays.
- **Secret rotation:** per-endpoint secret stored on `passwordpolicy_webhook_endpoints.secretCurrent`. Admins generate a new secret via the CP, the old secret moves to `secretPrevious` with a configurable grace window (default 24h, capped at 7 days). During the grace window both secrets are accepted by signature verification on the consumer side — but the plugin signs with `secretCurrent` only. On grace expiry, `secretPrevious` is null'd out via a queue job.

The HMAC is computed over `timestamp.eventId.body` (period-delimited concatenation), then `hash_hmac('sha256', $message, $secretCurrent)`. Document the canonical message format in G9 layer 1 PHPDoc.

### 5. `AlertCooldownService` scope

Generalises the per-(event-class, key) dedup pattern from F2's `_hasRecentNotification()` and `sendAdminSecurityAlert()`'s 5-minute filter. New service consolidates both.

**Storage:** new table `passwordpolicy_alert_cooldowns`. Cache layer in front for hot reads.

Why a table and not cache-only: per `project_audit_capture_principle.md`, "did we suppress an alert?" must be answerable from the database — cache-only loses that history on flush. An auditor asking "you had a credential stuffing attack on 2026-05-04 — show me the alert suppression record" needs durable storage.

**Schema:**

- `id` (primary key)
- `eventClass` (string, indexed) — e.g. `hibp_login_burst`, `group_deletion_cascade`, `force_reset_burst`
- `cooldownKey` (string, indexed) — e.g. `user:123`, `group:5`, `global`
- `firedAt` (datetime, indexed)
- Composite index on `(eventClass, cooldownKey, firedAt)` for the dedup query path
- No `id` FK constraints (events outlive entities by design)

**API:**

```php
// Returns true if the alert may fire now; records the fire on true return.
$cooldown->shouldFire(string $eventClass, string $cooldownKey, int $cooldownSeconds): bool;

// Explicit record without a should-fire check (for callers that want to record + send unconditionally).
$cooldown->recordFire(string $eventClass, string $cooldownKey): void;

// GC pruner — drop rows older than the longest cooldown configured (or 7 days, whichever wins).
$cooldown->pruneOldEntries(): int;
```

**Event classes registered in 5.2.0:**

| Event class | Default cooldown | Cooldown key shape |
|---|---|---|
| `hibp_login_burst` | 24h | `prefix:<5char-sha1-prefix>` (catches mass detection of one breached password against many users) |
| `group_deletion_cascade` | 5m | `group:<groupId>` (admin nukes a 5000-user group — one alert, not per-user) |
| `force_reset_burst` | 5m | `actor:<adminId>` (admin runs SendPasswordResetEmail bulk on a large set) |
| `expiry_reminder` | window-driven | `user:<userId>` (migrated from F2's `_hasRecentNotification()`) |
| `admin_security_alert:<event>` | 5m | `event:<event>` (migrated from F2's 5-minute admin-alert filter) |

The default cooldowns are **configurable per-class** via a settings array (`alertCooldowns: ['hibp_login_burst' => 86400, ...]`). Operators who want shorter HIBP-on-login windows for testing override.

**Migration of F2's existing dedup:** factor the `_hasRecentNotification()` and the admin-alert 5-minute filter out of `NotificationService` into `AlertCooldownService::shouldFire()`. Existing `passwordpolicy_notification_log` rows continue to drive the dedup story for the operational read-back ("did this user actually get an email last Tuesday?") — but the dedup decision moves to the cooldown service. Two storage surfaces: `notification_log` (what was sent + when + with what subject/body) and `alert_cooldowns` (when alerting fired regardless of whether an email or row was emitted).

### 6. Streaming audit-log export

`AuditController::actionExport` extension. New `AuditExportJob extends BaseBatchedJob` mirrors P1.4's `SendPasswordExpiryRemindersJob`:

- `batchSize: 1000`
- Per-batch streams to a temp file in `storage/runtime/password-policy/exports/<uid>.<format>`.
- On completion, fires `AuditExportCompleteEvent` with the file path + format + row count + admin id.

**Output formats:** CSV + JSON-Lines (one JSON object per line). NOT a single mega JSON array — JSON-Lines is what downstream tooling actually wants, and PHP can stream-write it without a memory ceiling.

**Streaming response.** Generate a presigned download URL on completion. Filesystem-backed via Craft's `\craft\base\FsInterface` so admins can target an S3 bucket via a configured filesystem if they want defense-in-depth for the "100M-row audit dump" case. Default: local filesystem at `@runtime/password-policy/exports`. Configurable via new setting `auditExportFilesystem` (string handle, defaults to local).

**Permission:** new permission `pp:audit-export`. Separate from `pp:audit-view` — granting export is an explicit decision (export carries off-site data).

**Synchronous shortcut.** When the date range is bounded and `< 30 days` AND row count `< 1000`, skip the queue and stream the response directly via `Craft::$app->getResponse()->stream(...)`. Same code path on the receiving end (file generated identically), but the admin doesn't wait for queue runner.

### 7. Phase G subset scope

User-confirmed 2026-05-06. See § Scope decisions at the end of this plan for the full table. Summary:

- **Ships in 5.2.0:** G1 through G12, all in full. No half-shipped features.
- **Defers to 5.3:** Phase 12 § REST surface (ApiTokenService + ApiController). Substantial layer on its own; G10's streaming export covers the batch-import-to-SIEM use case in 5.2.0.
- **Cut from the matrix entirely (not parked, not deferred):** syslog UDP forwarder. UDP is unreliable for audit forwarding; TCP/TLS is the compliance-correct default.

---

## Build order rationale

Foundation-first per the C2 plan idiom. The audit hash chain is the foundation — every later G item reads from or forwards from `passwordpolicy_audit_log` once the chain is in place. Compliance dashboard and forwarders are read-side; they cannot ship before the writes they depend on.

| Order | Item | Why |
|---|---|---|
| 1 | **G1 — Audit hash chain (writes + canonicalisation)** | Foundation. Schema migration + `AuditLogService` rewrite + recompute migration for existing rows. Everything else depends on the chain shape. |
| 2 | **G2 — Independent verifier CLI** | Read-side validation of G1. Runnable against the playground's existing rows after G1's recompute migration. Locks the canonical-JSON format because the verifier produces the same hashes the writer produces. |
| 3 | **G3 — Compliance dashboard + report exports** | Visible Enterprise UI that depends on the chain being in place + the verifier existing. Big single feature. |
| 4 | **G4 — Field-level before/after diffs on policy changes** | Augments the chain with structured diff payloads on policy-edit events. Builds on G1 (the diff goes in `details` JSON which is part of the canonical payload). |
| 5 | **G5 — Per-event PII allowlist registered per event type** | Refactors the existing single global allowlist into a per-event-class registry. Builds on G1 (no schema change, but the canonicalisation layer now validates against the per-event registry before insert). Fails closed. |
| 6 | **G6 — Per-policy custom blocklist editor** | Independent of the chain work. `policyId` column shipped in P1.11. Editor surface + validator merge. |
| 7 | **G7 — `AlertCooldownService`** | New table + service. Migrate F2's `_hasRecentNotification()` + the admin-alert 5-min filter to the new service. Independent of G1–G6 but lands here because G8 depends on it (SIEM forwarder failures register cooldowns). |
| 8 | **G8 — SIEM forwarder (syslog over TLS only)** | Reads from G1's chain. Uses G7 for circuit-breaker cooldowns. Reuses the BaseBatchedJob template from P1.4. |
| 9 | **G9 — Webhook forwarder (full surface)** | Schema + service + HMAC signing + secret rotation + CP management UI + endpoint CRUD screen. Ships whole in 5.2.0 — half-shipping the infra without the management UI was rejected after review (creates a "you have webhooks but can't make one without a console" gap that rots). |
| 10 | **G10 — Streaming audit-log export** | Extends `AuditController::actionExport` + new `AuditExportJob`. Builds on G1's chain shape because the export emits canonical-JSON rows. |
| 11 | **G11 — Custom email template paths (Enterprise)** | Extends `passwordpolicy_notification_templates` JSON content shape with `templatePath`. Pure read-side from `NotificationService::composeFromTemplate`. Independent of G1. Strip-on-save defense gates Pro from writing it. |
| 12 | **G12 — Enterprise notification keys (`new-device-alert`, `admin-security-alert`)** | Move both to the editable-templates surface. F2 currently captures their `_dispatchMailerKey` outcomes without subject/body — G12 upgrades them to full `_dispatch()` capture. Migration adds the two seed rows per site. |

---

# G1 — Audit hash chain (writes + canonicalisation)

Foundation. Schema migration + `AuditLogService::logEvent()` rewrite + recompute migration for existing rows. Lands before any other Phase G work.

## Layer 1 — Schema migration

**Build**

- Generate migration via `ddev craft migrate/create AddRowHashAndPreviousHashToAuditLog --plugin=password-policy`. Use the generated filename verbatim.
- Migration body: `addColumn` `rowHash CHAR(64) NOT NULL DEFAULT '0'` (default placeholder so the NOT NULL add doesn't blow up on existing rows — recompute migration in layer 4 fills real values), `addColumn` `previousHash CHAR(64) NOT NULL DEFAULT '0'`, `addColumn` `forwardedAt DATETIME NULL`, `addColumn` `forwardAttempts INT NOT NULL DEFAULT 0`. Idempotent guards via `getColumn()` checks.
- Add index on `forwardedAt` (forwarder query path: `WHERE forwardedAt IS NULL`).
- Update `Install.php::_createAuditLogTable()` to mirror — same column shape on fresh installs. No default values for `rowHash` / `previousHash` on Install.php (fresh installs go through the chain-aware `logEvent` from the first row).
- Bump `PasswordPolicy::$schemaVersion` from 2.4.0 to 2.5.0.

**Verify**

- `ddev craft migrate/up --plugin=password-policy` succeeds. Inspect via `ddev craft db/dump`-equivalent or `ddev craft project-config/get`-style introspection — confirm new columns exist on `passwordpolicy_audit_log`.
- `ddev craft plugin/uninstall password-policy && ddev craft plugin/install password-policy` round-trips cleanly. New columns present from the fresh install path.
- Re-run `migrate/up` — second invocation no-ops (idempotent guard works).

## Layer 2 — `AuditLogService` rewrite

**Build**

- Add static method `AuditLogService::canonicalize(array $payload): string`. Document the canonical-JSON contract (alphabetical key order, no whitespace, `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`, null-preserving, recursive sort). Use `ksort($payload, SORT_STRING)` recursively before encoding.
- Refactor `logEvent()`:
  - Wrap the row build + insert in a `Craft::$app->getDb()->transaction(function () {...})` block.
  - Inside the transaction, query the latest row's `rowHash` with `forUpdate()`. Default to `str_repeat('0', 64)` when no row exists (genesis case).
  - Build the canonical payload — alphabetical keys, the formatted `dateCreated` string per the locked format `Y-m-d\TH:i:s\Z` in UTC, the already-allowlist-filtered `details` JSON, all the fields enumerated in § 1 of locked architecture.
  - Compute `$rowHash = hash('sha256', $canonicalPayload . $previousHash)`.
  - Set `$record->rowHash` + `$record->previousHash` before save.
- **Capture is universal.** Remove the `if (!getIsEnterprise()) { return; }` early-return at the top of `logEvent()`. Edition gates apply to the dashboard / verifier UI / forwarder / export / dashboards — not to the underlying write. Keep the existing `if (!$settings->enableAuditLog) { return; }` toggle (admin-managed feature flag, distinct from edition).
- Add PHPDoc + section header per `coding-style.md`. Privacy comment block at the top of the class explaining the canonical payload contract — auditor-facing readability.

**Verify**

- Pest test: write a known-shape row, fetch it back, assert `rowHash === hash('sha256', AuditLogService::canonicalize($expectedPayload) . str_repeat('0', 64))`. Bit-identical to a hand-rolled reference.
- Pest test: write three rows in sequence, assert row 2's `previousHash` matches row 1's `rowHash`, row 3's `previousHash` matches row 2's `rowHash`.
- Pest test: simulate concurrent insert via two-process fixture (or `Db::transaction` with `forUpdate` mock) — assert no duplicate `rowHash` and chain is contiguous. (May need to defer to manual test on the playground if DB-level concurrent-test infra isn't available; tag as T14.x in `manual-tests.md` if so.)
- Switch playground to **Lite** edition. Trigger a `password_changed` event (change a user's password). Confirm: row written to `passwordpolicy_audit_log` with `rowHash` populated. Capture-on-every-edition holds.
- Switch back to Enterprise. Same flow. Same row write. (Difference is which surfaces consume the rows downstream — Lite has no dashboard, no verifier UI, no forwarder.)

## Layer 3 — Canonicalisation determinism tests

**Build**

- Pest test file `tests/Integration/Services/AuditCanonicalisationTest.php`. Cover:
  - Key reordering: input `['z' => 1, 'a' => 2]` produces same canonical output as `['a' => 2, 'z' => 1]`.
  - Nested key reordering: nested arrays sort recursively.
  - Null preservation: input `['k' => null]` produces `{"k":null}`, NOT `{}`.
  - Boolean encoding: `true` produces `true`, NOT `1`.
  - Unicode passthrough: input with `é` produces `é` in output (not `\u00e9`).
  - Slash passthrough: input with `/` produces `/` (not `\/`).
  - Integer passthrough: `42` produces `42` (not `"42"`).
- Pest fixture file with golden canonical strings for a representative payload set. Add a regression test that the golden strings don't drift over future code changes.

**Verify**

- `ddev composer test --filter=AuditCanonicalisationTest` green.
- ECS clean, PHPStan clean.

## Layer 4 — Recompute migration for existing rows

**Build**

- Generate migration via `ddev craft migrate/create RecomputeAuditLogChain --plugin=password-policy`.
- Migration body: walk all existing rows in `id ASC` order, recompute `rowHash` for each row (using the already-stored `dateCreated` + the chain-walked `previousHash`), update in place. Idempotent guard: skip rows where `rowHash != '0' x 64` (already populated by a prior run of this migration).
- Toggle `enableLogging` + `enableProfiling` off before the loop, restore in `finally`. Per `migrations.md` rule for batch-write migrations — Yii's debug logger would otherwise capture every recompute at SQL bind time, bloating the log.
- Wrap in `try/finally` to ensure the toggle restoration runs even on failure.

**Verify**

- Playground has existing `passwordpolicy_audit_log` rows from earlier sessions (HIBP-on-login + force-reset events from manual testing). Run the migration. Confirm: every row now has a non-zero `rowHash`. Run `password-policy/audit/verify` (G2 layer 1 — verify that step lands after this layer's verify gate).
- Re-run the migration. Confirm: idempotent guard short-circuits, no double-recompute.

## Layer 5 — Audit chain rotation event

**Build**

- New event class `src/events/AuditChainRotatedEvent.php`. Properties: `int $startId`, `int $endId`, `string $startRowHash`, `string $endRowHash`, `\DateTime $rotatedAt`. PHPDoc + section header + `@event` markup.
- Fire from `AuditLogService::purgeOldEntries()` after a successful prune, before returning. Payload reflects the now-first row's hash (as the new chain-start anchor) and the highest deleted id (so consumers can detect retention boundaries).
- Register `EVENT_AUDIT_CHAIN_ROTATED` constant on `AuditLogService`.
- Add a row to `docs/user/reference/events.md`. Edition: Enterprise.

**Verify**

- Manually trigger a prune via `password-policy/gc/run` (or a one-shot console action with an aggressive `--days=0` flag if the existing GC doesn't expose a Trigger-now path). Confirm: event fires, payload populated correctly. Add a temporary listener in `tests/Integration/Services/AuditChainRotatedEventTest.php` that asserts properties.

## Commit

`feat(audit): hash-chained audit log rows + canonicalisation + recompute migration (G1)`

Body: explain the canonical-JSON shape (`Y-m-d\TH:i:s\Z` UTC dateCreated, alphabetical keys, null-preserving, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE), the `previousHash = '0' x 64` genesis contract, the SELECT FOR UPDATE concurrency guard, the `forwardedAt` + `forwardAttempts` columns added for G8, and the recompute migration's debug-logger-toggle defense. How to undo: drop the new columns + revert the schema version + reapply the prior `AuditLogService::logEvent()` (the no-chain version). Match the depth of `7b9d7b7` and `04178bf`.

---

# G2 — Independent verifier CLI

Read-side validation of G1. Locks the canonical-JSON format because the verifier reproduces the writer's hashes.

## Layer 1 — Console controller

**Build**

- New `src/console/controllers/AuditController.php` (or extend the existing one if it already houses `purge` / `export` from the prior Phase 4 work — read first, don't duplicate). Add `actionVerify` method.
- Method signature: `actionVerify(): int`. Reads `--from`, `--to`, `--json`, `--quiet` from the controller's `defineOptions()`.
- Walk the chain in `id ASC` order (within the bounded range if flags set).
- For each row:
  - Reconstruct the canonical payload using `AuditLogService::canonicalize()`.
  - Compute `$expected = hash('sha256', $payload . $row['previousHash'])`.
  - Compare to `$row['rowHash']`. On mismatch: print error (with row id, dateCreated, computed hash, stored hash), return `ExitCode::DATAERR` (1).
  - On `previousHash` mismatch with prior row's `rowHash`: same error path. Don't keep walking past a break — first break is enough to fail the audit.
- Retention-purged-row tolerance: detect by checking whether the first row's `previousHash` references a row that doesn't exist. Compare the first surviving row's `dateCreated` to `now() - retentionDays + 24h`. If older, accept as chain-start sentinel. If newer, fail.
- Open-source mandate comment at the top of `actionVerify` (see § 2 of locked architecture).
- Top-level comment block also documenting: this method must produce bit-identical canonical strings to `AuditLogService::canonicalize()` — they share the same code path, but in case a future maintainer is tempted to inline a "fast path" verifier, the comment forbids it.

**Verify**

- `ddev craft password-policy/audit/verify` against the playground (post G1-recompute). Exit code 0. Output lists `OK: N rows verified`.
- Manually corrupt one row's `event` column via raw SQL (`UPDATE passwordpolicy_audit_log SET event = 'tampered' WHERE id = X`). Re-run verify. Exit code 1. Output names the row id, dateCreated, computed hash, stored hash. Restore the row to its original state.
- `ddev craft password-policy/audit/verify --json`. Inspect output — JSON Lines with one object per row plus a summary line. Pipe to `jq` to confirm parseable.
- `ddev craft password-policy/audit/verify --from=10 --to=20`. Confirm: only rows 10–20 walked.

## Layer 2 — Permission registration

**Build**

- Register `pp:audit-verify` permission in `PasswordPolicy::_registerPermissions()` (or wherever the existing permission registration lives — check `architecture.md` § scaffolding).
- Permission docblock: "Run the audit-log verifier CLI. Auditor-grantable without full admin."

**Verify**

- Visit `/admin/users/groups/<groupId>` in the CP. Confirm: new permission appears in the password-policy section.

## Layer 3 — Pest tests

**Build**

- `tests/Integration/Console/AuditVerifyTest.php`. Cases:
  - Empty audit log → exit 0 with `OK: 0 rows verified`.
  - Single-row chain → exit 0.
  - Three-row valid chain → exit 0.
  - Three-row chain with row 2 corrupted → exit 1 with row 2 id in output.
  - Three-row chain with row 2's `previousHash` corrupted (broken from prior `rowHash`) → exit 1.
  - Retention boundary: first surviving row older than retention window with non-zero `previousHash` → exit 0.
  - Retention boundary: first surviving row recent with non-zero `previousHash` referencing nonexistent row → exit 1.
  - `--from` / `--to` bounds: corruption outside the bounded range → exit 0 (not detected because we didn't walk that range).

**Verify**

- `ddev composer test --filter=AuditVerifyTest` green.
- ECS clean, PHPStan clean.

## Commit

`feat(audit): independent verifier CLI with retention-purge tolerance + JSON output (G2)`

Body: enumerate the exit codes (0 valid, 1 break, 2 unreadable), the `--from`/`--to`/`--json`/`--quiet` flag semantics, the retention-purged-row boundary handling, the `pp:audit-verify` permission gating, and the open-source mandate. How to undo: revert the `actionVerify` method + drop the permission registration.

---

# G3 — Compliance dashboard + report exports

Largest single Phase G feature. Visible Enterprise UI on top of G1's chain + G2's verifier.

## Layer 1 — Dashboard utility scaffolding

**Build**

- Generate via `ddev craft make` (interactive scaffolder picks the utility template). New `src/utilities/ComplianceDashboardUtility.php` extending `\craft\base\Utility`.
- `displayName(): string` returns "Compliance dashboard". `id()`, `iconPath()`, `contentHtml()`.
- Edition gate in `static iconPath()` and the `_registerUtilities()` method on `PasswordPolicy.php` — only registers on Enterprise.
- `contentHtml()` renders `templates/_utilities/compliance-dashboard.twig`. Pass `aggregates` + `lastVerifierRun` + `pendingForwards` + `orphanedAlertCooldowns` to the template.

**Verify**

- Switch playground to Enterprise. Visit `/admin/utilities`. Confirm: "Compliance dashboard" listed.
- Click into it. Empty placeholder content renders.
- Switch to Pro. Confirm: utility no longer in the list.

## Layer 2 — Aggregates service

**Build**

- New `src/services/ComplianceAggregateService.php`. Public methods:
  - `getTotals(): array` — total audit rows, rows in last 30 days, by event class.
  - `getChainHealth(): array` — last verifier-run time + result, broken-chain count (cached for 5 minutes — verifier walks the whole table; we don't run on every dashboard hit).
  - `getAlertCooldownActivity(): array` — fires by event class, last 24h.
  - `getPendingForwards(): array` — count of rows with `forwardedAt IS NULL`, oldest pending row's age.
  - `getRetentionStatus(): array` — current retention setting + oldest row + projected next-prune date.
- Register service in `ServicesTrait`.

**Verify**

- One-shot from a temp Twig template or the dashboard render — confirm aggregates return reasonable values against the playground state.

## Layer 3 — Dashboard template

**Build**

- `src/templates/_utilities/compliance-dashboard.twig`. Sections:
  - "Audit chain status" — last verifier run + outcome. Use `<blockquote class="note tip">` on healthy state, `<blockquote class="note warning">` on a broken chain. Verifier last-run time formatted via `|datetime('long')`.
  - "Activity in last 24h" — table of fires by event class. `forms.editableTableField` not appropriate (read-only); plain `<table class="data fullwidth">` is the canonical Craft pattern for read-only data tables.
  - "Pending SIEM forwarding" — count + oldest age. Note callout with link to `/admin/password-policy/forwarders` (G8).
  - "Retention" — current setting + oldest row + next prune date.
- Each section has a "Run report" link to a new controller action (Layer 4).

**Verify**

- Render against the playground. Confirm: numbers populate, callouts render correctly.

## Layer 4 — Report controller (HTML / CSV)

**Build**

- New `src/controllers/ReportController.php` extending `\craft\web\Controller`. Permission: `requirePermission('pp:audit-view')`.
- Actions:
  - `actionHtml($report)` — renders an HTML report for the given key (audit-summary, alert-activity, retention-projection).
  - `actionCsv($report)` — downloads a CSV of the same. Edition-gated to Enterprise (defense-in-depth — utility is only registered on Enterprise but a crafted GET to the controller route shouldn't bypass).
- URL rules: `password-policy/reports/<report>/html` + `password-policy/reports/<report>/csv`.
- HTML output uses Craft's CP layout; CSV streams via `Craft::$app->getResponse()->stream()` for large reports. PDF deferred (separate concern; nice-to-have, not load-bearing for compliance evidence — the user can print-to-PDF the HTML).

**Verify**

- Visit `/admin/password-policy/reports/audit-summary/html` as Enterprise admin. Renders.
- Visit `/admin/password-policy/reports/audit-summary/csv`. Downloads CSV. Open in spreadsheet tool — looks right.
- Switch to Pro. Visit the URL. 403 Forbidden.

## Layer 5 — Pest tests

**Build**

- `tests/Integration/Services/ComplianceAggregateServiceTest.php`. Cover each `get*()` method against fixture rows.
- `tests/Integration/Controllers/ReportControllerTest.php`. Cover Enterprise-only edition gate, permission gate, CSV format.

**Verify**

- `ddev composer test --filter=Compliance` green.
- ECS clean, PHPStan clean.

## Commit

`feat(compliance): dashboard utility + aggregate service + HTML/CSV report controller (G3)`

Body: dashboard sections, aggregate service surface, edition gating, defense-in-depth on the controller. PDF intentionally deferred (print-to-PDF the HTML is sufficient for evidence packages). How to undo: drop the utility + service + controller + URL rules.

---

# G4 — Field-level before/after diffs on policy changes

Augments G1's chain payload with structured diffs. Builds on the Phase 11 (c) decision in `audit-logging.md`.

## Layer 1 — Diff capture in `PolicyService::beforeSavePolicy()`

**Build**

- In `PolicyService::beforeSavePolicy()` (or wherever the pre-save listener fires — verify against current code), load the existing record by ID.
- Compare loaded record to incoming payload field-by-field. Build `$diff` array shaped as `{fieldName: {old: <value>, new: <value>}}`. Omit unchanged fields.
- Boolean tri-state fields: emit `null` / `true` / `false` literally. Array-valued fields (`groupIds`, `notificationKeys`): emit the full old + new arrays.
- Stash the diff on a service-level scratch property keyed by policy id (`$pendingDiffs[$policyId] = $diff`) so the after-save event handler can pick it up.

**Verify**

- Edit a named policy in the CP. Set a logging assertion in `PolicyService::beforeSavePolicy()`. Confirm: diff shape matches expectations.

## Layer 2 — `policy_changed` event listener

**Build**

- Listen on `PolicyService::EVENT_AFTER_SAVE_POLICY`. Read the stashed diff, fire `AuditLogService::logEvent('policy_changed', ['policyId' => ..., 'policyName' => ..., 'diff' => $diff])`.
- Add `policy_changed` to G5's per-event allowlist as `['policyId', 'policyName', 'diff']`.

**Verify**

- Edit a named policy. Confirm: audit row written with `event = 'policy_changed'`, `details.diff` populated.
- Inspect via `password-policy/audit/verify` — chain still verifies (rowHash includes the diff in its canonical payload).

## Layer 3 — Pest tests

**Build**

- `tests/Integration/Services/PolicyDiffCaptureTest.php`. Cover: field change → diff present, unchanged fields → omitted, boolean tri-state → null/true/false, array fields → full arrays.

**Verify**

- `ddev composer test --filter=PolicyDiff` green.

## Commit

`feat(audit): policy_changed event with field-level before/after diffs (G4)`

Body: diff shape, before/after capture mechanics, scratch-property lifetime contract (cleared after the after-save handler fires; PolicyService is request-scoped). Maps to ISO 27002 A.5.37 + SOC 2 CC8.1 + NIS2 Article 21(2)(e). How to undo: revert the listener + drop the diff registry entry.

---

# G5 — Per-event PII allowlist registered per event type

Refactors the existing single global `ALLOWED_DETAIL_KEYS` constant in `AuditLogService` into a per-event-class registry. Fails closed.

## Layer 1 — Registry data structure

**Build**

- New constant `AuditLogService::ALLOWED_DETAILS_BY_EVENT`:

```php
private const ALLOWED_DETAILS_BY_EVENT = [
    'password_changed' => ['source', 'method', 'reason'],
    'password_reset_forced' => ['source', 'reason'],
    'hibp_breach_detected' => ['source', 'failMode'],
    'hibp_check_failed' => ['source', 'failMode'],
    'account_locked' => ['source'],
    'account_unlocked' => ['source'],
    'policy_changed' => ['policyId', 'policyName', 'diff'],
    // ...one entry per event class fired by the plugin
];
```

- Replace the `array_intersect_key($details, array_flip(self::ALLOWED_DETAIL_KEYS))` line in `logEvent()` with a per-event lookup against `ALLOWED_DETAILS_BY_EVENT[$event]`.
- **Fail closed:** if `$event` not in the registry, log warning + drop the audit row (return early without insert). Add a test case that verifies this.
- Document the registry contract in a class-level docblock: every fired event class must register its allowlist; new events that fire without registration trigger the fail-closed warning.

**Verify**

- Pest: write an event with `$event = 'unregistered_event'`. Confirm: no row written, warning logged.
- Pest: write `password_changed` with extra non-allowlisted keys (`'plaintext' => 'abc'`). Confirm: row written, `details` contains only allowlisted keys.
- Existing audit log rows continue to pass verification (canonical-JSON output unchanged for already-allowlisted shapes).

## Layer 2 — Inspection surfaces

**Build**

- Console action `password-policy/audit/schema`. Outputs the registry as a human-readable table or JSON (with `--json` flag). Auditors can read the static evidence: "this is what every event class is permitted to log."
- CP utility `AuditSchemaUtility` extending `\craft\base\Utility`. Renders the registry as a read-only table. Edition-gated to Enterprise + permission-gated to `pp:audit-view`.

**Verify**

- `ddev craft password-policy/audit/schema`. Confirm output.
- `/admin/utilities/audit-schema` renders.

## Layer 3 — Test enforcement

**Build**

- `tests/Integration/Services/AuditAllowlistRegistryTest.php`. Pest fixture that:
  - Reflects on `AuditLogService::ALLOWED_DETAILS_BY_EVENT`.
  - Greps the codebase for every `AuditLogService::logEvent('...', ...)` call site (use a static `Grep` strategy or precomputed list of event classes).
  - Asserts every event class fired in the codebase has a registry entry.
  - Fails the test if a new event class is added without a registry entry.

**Verify**

- `ddev composer test --filter=AuditAllowlistRegistry` green.

## Commit

`feat(audit): per-event PII allowlist registry with fail-closed enforcement (G5)`

Body: replaces the global allowlist constant with a per-event registry, fail-closed semantics, inspection surfaces (CLI + utility), test-enforcement of new event registration. Maps to: privacy-by-design USP, SOC 2 CC6.6 evidence, NIS2 Article 21(2)(b) measurable claim. How to undo: revert to the single global constant + drop the inspection surfaces.

---

# G6 — Per-policy custom blocklist editor

Enterprise extension of P1.11. Schema's `policyId` column already shipped at install time.

## Layer 1 — Service extension

**Build**

- Extend `BlocklistService::addCustomWord(string $word, ?int $policyId = null): void`. Existing global path passes `policyId = null`; new per-policy path passes the policy id.
- New method `BlocklistService::getWordsForPolicy(?int $policyId): array` — returns global words + per-policy words for the given policy.
- `CommonPasswordValidator` gets a constructor parameter or service injection point so it can call `getWordsForPolicy($resolvedPolicy->id)` instead of fetching only global words.
- Cache key includes `policyId` set: `pp:blocklist:words:<sortedPolicyIds-as-csv-or-null>`.

**Verify**

- Pest: add a per-policy word, fetch `getWordsForPolicy(<policyId>)`. Confirm: word present.
- Pest: validate a password matching the per-policy word against the user resolved to that policy. Confirm: rejected with the per-policy "blocked" error.
- Validate the same password against a user not resolved to the policy. Confirm: not rejected (per-policy scope held).

## Layer 2 — CP editor surface

**Build**

- New tab on the policy edit screen: "Custom blocklist". Renders an `forms.editableTableField` scoped to `policyId = <currentPolicy->id>`. Same diff-on-save pattern as the global blocklist editor (numeric rowId = keep, non-numeric = insert, missing = delete).
- POST handler: extend `PolicyController::actionSave` to absorb the custom-blocklist editable-table payload alongside the rest of the policy fields. Single transaction.
- Edition-strip on save: in `PolicyController::actionSave`, unset the per-policy blocklist payload when running on Pro/Lite. **Add this strip in the same commit** — defense-in-depth.

**Verify**

- Switch to Enterprise. Edit a policy. Add custom blocklist words. Save. Confirm: words appear in `passwordpolicy_blocklist` with `policyId = <policy id>`.
- Switch to Pro. Edit the same policy via crafted POST containing the per-policy payload. Confirm: payload silently stripped — no per-policy rows added.

## Layer 3 — Pest tests

**Build**

- `tests/Integration/Services/PerPolicyBlocklistTest.php`. Cover service surface + cache invalidation.
- `tests/Integration/Controllers/PolicyControllerCustomBlocklistTest.php`. Cover edition-strip path on Pro.

**Verify**

- `ddev composer test --filter=Blocklist` green (covers existing P1.11 tests + the new ones).

## Commit

`feat(blocklist): per-policy custom blocklist editor + validator merge (G6)`

Body: service surface extension, CP editor tab, edition-strip defense-in-depth, validator merge logic. How to undo: revert the editor template + the controller diff + the validator extension.

---

# G7 — `AlertCooldownService` (factor out from F2)

New table + service. Migrate F2's existing dedup paths.

## Layer 1 — Migration

**Build**

- Generate via `ddev craft migrate/create AddAlertCooldownsTable --plugin=password-policy`. Use the generated filename.
- `safeUp`: create `passwordpolicy_alert_cooldowns` table per § 5 of locked architecture (id, eventClass, cooldownKey, firedAt + composite index).
- Update `Install.php` to mirror — new private method `_createAlertCooldownsTable()`, called in `safeUp` in correct FK order (no FKs on this table).
- Bump `PasswordPolicy::$schemaVersion` (from G1's 2.5.0 → 2.6.0).

**Verify**

- `ddev craft migrate/up --plugin=password-policy` succeeds. Table exists.
- Plugin uninstall + reinstall round-trips cleanly.

## Layer 2 — Service

**Build**

- New `src/services/AlertCooldownService.php`. Public methods per § 5: `shouldFire`, `recordFire`, `pruneOldEntries`. Add cache-layer wrap on `shouldFire` for hot reads (cache key: `pp:alert-cooldown:<eventClass>:<cooldownKey>`, TTL = cooldownSeconds).
- Register in `ServicesTrait`.
- `AlertCooldownEvent` event class — new file `src/events/AlertCooldownEvent.php`. Fires after `recordFire` succeeds. Payload: `eventClass`, `cooldownKey`, `firedAt`. Edition: every (capture-on-every-edition).

**Verify**

- Pest: call `shouldFire('test', 'key', 60)` twice in succession. First returns `true` (records the fire), second returns `false` (within cooldown). Wait > 60s, third returns `true` again.

## Layer 3 — Migrate F2's existing dedup

**Build**

- Replace `NotificationService::_hasRecentNotification($userId, $type)` body with `return !$cooldown->shouldFire('expiry_reminder', "user:{$userId}", $window)`. Note the inverted return — `shouldFire = true` means "ok to fire" while `_hasRecentNotification = true` means "skip the fire". Carefully invert. Add a regression test.
- Replace the `sendAdminSecurityAlert()` 5-minute filter similarly: `if (!$cooldown->shouldFire('admin_security_alert:' . $event, 'event:' . $event, 300)) { return; }`.
- The `notification_log` row write contract is unchanged — capture still happens on every dispatch. The cooldown service decides whether the dispatch fires at all.

**Verify**

- Trigger an expiry reminder twice within the window. Confirm: only one row in `notification_log` with `status = 'sent'`. (Existing F2 behavior — must not regress.)
- Trigger admin alerts for the same event twice within 5 minutes. Confirm: only one row.

## Layer 4 — GC integration

**Build**

- Add `AlertCooldownService::pruneOldEntries()` call to the existing `gc/run` console action. Documentation note in `feedback_retention_gc_framing.md`-aware language: the prune is recommended production setup via cron, not edge case.

**Verify**

- `ddev craft password-policy/gc/run` succeeds. New rows in `alert_cooldowns` older than the threshold are removed.

## Layer 5 — Pest tests

**Build**

- `tests/Integration/Services/AlertCooldownServiceTest.php`. Cover `shouldFire` + `recordFire` + `pruneOldEntries` + cache-layer hit/miss.
- `tests/Integration/Services/NotificationServiceCaptureTest.php` — already exists (F2). Verify the F2 dedup behavior unchanged after refactor.

**Verify**

- `ddev composer test --filter=AlertCooldown` green.
- Existing F2 tests continue to pass — no regression.

## Commit

`feat(alerts): AlertCooldownService factored out from notification-log dedup (G7)`

Body: new table + service + cache layer + F2 migration. Why a table over cache-only (project_audit_capture_principle). How to undo: revert the service + migrate the dedup back into NotificationService.

---

# G8 — SIEM forwarder (syslog over TLS only)

First forwarder. Webhook infra in G9.

## Layer 1 — Schema migration

**Build**

- Generate via `ddev craft migrate/create AddSiemForwardersTable --plugin=password-policy`. Use the generated filename.
- Create `passwordpolicy_siem_forwarders` table per § 3 of locked architecture.
- Update `Install.php` to mirror.
- Bump schema version (2.6.0 → 2.7.0).

**Verify**

- `ddev craft migrate/up --plugin=password-policy` succeeds. Table exists.

## Layer 2 — `SiemService`

**Build**

- New `src/services/SiemService.php`. Public methods:
  - `forward(AuditLogRecord $row, SiemForwarderRecord $forwarder): bool` — synchronous syslog-over-TLS send. Return true on success.
  - `getActiveForwarders(): array` — returns forwarders where `enabled = true` and circuit not open.
  - `getEligibleEventClasses(SiemForwarderRecord $forwarder): array` — merges per-forwarder override with global setting.
- Syslog-over-TLS: open a TLS stream socket via `stream_socket_client('tls://host:port', ...)`, write the RFC 5424 syslog frame, close. Use TLS verify per the forwarder's `tlsCertVerify` field; load CA bundle via `App::parseEnv($forwarder->tlsCaBundlePath)` when set.
- Register in `ServicesTrait`.

**Verify**

- One-shot: configure a fake syslog endpoint via `nc -lk 6514` in DDEV, set up a forwarder pointing at it. Trigger an audit event. Confirm: bytes arrive at `nc`.

## Layer 3 — `SiemForwardJob`

**Build**

- New `src/jobs/SiemForwardJob.php` extending `BaseBatchedJob`. Mirror P1.4's pattern (`batchSize: 100`, `getTtr: 300`, `canRetry: < 5`).
- `loadData()` returns a `UnforwardedAuditRowBatcher` — campaign-style query for rows where `forwardedAt IS NULL` AND `event` is in `getEligibleEventClasses()`.
- `processItem`: for each active forwarder, call `SiemService::forward(...)`. On success, set `forwardedAt = NOW()`, increment a per-forwarder success counter (cache key for circuit half-open detection). On failure, increment `forwardAttempts`, increment forwarder's `consecutiveFailures`, check circuit breaker — open it on threshold.
- Edition-gate via `$plugin->getIsEnterprise()` at `execute()` top — same pattern as P1.4.

**Verify**

- Manually enqueue a `SiemForwardJob`. Run `ddev craft queue/run`. Confirm: pending rows forwarded.
- Disable the syslog endpoint. Re-run. Confirm: rows fail to forward, `forwardAttempts` increment, `consecutiveFailures` increment, circuit opens after threshold.

## Layer 4 — CP forwarder management

**Build**

- New `src/controllers/SiemForwarderController.php`. CRUD for `passwordpolicy_siem_forwarders`. Permission: `pp:siem-manage` (new permission, register).
- New subnav: "SIEM forwarders" under the Notifications root or as a top-level Compliance subnav (decision: place under existing Notifications root for hierarchy, since forwarders are a delivery channel).
- Templates: `_siem/_index.twig` (table of forwarders), `_siem/_edit.twig` (edit screen with TLS settings + per-forwarder event-class allowlist override).
- Forwarder edit screen has a "Send test event" button — fires an `AuditLogService::logEvent('siem_test', ['source' => 'admin'])` and immediately enqueues a forward attempt.

**Verify**

- Visit `/admin/password-policy/siem`. Forwarders index renders.
- Add a new forwarder. Save. Re-edit. Confirm: round-trips.
- Click "Send test event". Confirm: arrives at the configured endpoint.

## Layer 5 — Edition strip on save

**Build**

- `SiemForwarderController::actionSave` rejects on non-Enterprise editions (`requireAdmin` + `requirePermission` per existing pattern, but also unconditionally `unset()` Enterprise keys at the top of `SettingsController::actionSave` for any settings-level fields the forwarder references). The forwarder list itself is gated by the permission + the subnav not registering on Pro/Lite.

**Verify**

- Switch to Pro. Visit `/admin/password-policy/siem`. 403 (or subnav simply doesn't register, which is the gentler fail).

## Layer 6 — Pest tests

**Build**

- `tests/Integration/Services/SiemServiceTest.php`. Test against an in-process TLS socket (or a stub forwarder that captures bytes).
- `tests/Integration/Jobs/SiemForwardJobTest.php`. Cover: success path, failure increments, circuit-open behavior, per-forwarder allowlist override.

**Verify**

- `ddev composer test --filter=Siem` green.

## Commit

`feat(siem): syslog-over-TLS forwarder + circuit breaker + CP management (G8)`

Body: new table + service + job + CP controller + edition gating. Circuit-breaker semantics. How to undo: drop the table + revert the controller + remove the subnav. UDP rejected outright (unreliable for audit forwarding; not parked, cut from the matrix). HTTP webhook ships in full as G9.

---

# G9 — Webhook forwarder (full surface)

Schema + service + HMAC signing + secret rotation + CP management UI + endpoint CRUD. Ships whole in 5.2.0. User-confirmed scope on 2026-05-06 — half-shipping the infrastructure without the CP surface was rejected after review (creates a "you have webhooks but can't make one without a console" gap).

## Layer 1 — Schema migration

**Build**

- Generate via `ddev craft migrate/create AddWebhookEndpointsTable --plugin=password-policy`. Use the generated filename.
- Create `passwordpolicy_webhook_endpoints` table:
  - `id`, `url` (string, env-var-resolved), `secretCurrent` (string, encrypted at rest via Craft's `\craft\helpers\Db::prepareValueForDb` + `Craft::$app->getSecurity()->encryptByKey()`), `secretPrevious` (nullable, same encryption), `secretRotatedAt` (nullable datetime), `eventClasses` (JSON), `enabled`, `consecutiveFailures`, `dateCreated`, `dateUpdated`, `uid`.
- Update `Install.php` to mirror. Bump schema version.

**Verify**

- Migration applies cleanly. Table exists.

## Layer 2 — `WebhookService`

**Build**

- New `src/services/WebhookService.php`. Public methods:
  - `dispatch(AuditLogRecord $row, WebhookEndpointRecord $endpoint): bool`.
  - HMAC signing per § 4 of locked architecture: header `X-PasswordPolicy-Signature: sha256=<hex>` over `timestamp.eventId.body`. Headers `X-PasswordPolicy-Timestamp` + `X-PasswordPolicy-Event-Id`.
  - Body: JSON serialisation of the audit row's canonical payload (reuse `AuditLogService::canonicalize()` so SIEM consumers and webhook consumers see the same representation).
  - HTTP via Guzzle with `'verify' => true` (TLS verify always on).
  - Register `EVENT_WEBHOOK_DELIVERY_ATTEMPT` for observability (fires regardless of outcome; payload includes endpoint id + status code + duration).

**Verify**

- Pest: dispatch against a `MockHandler`-stubbed Guzzle client. Confirm: headers correct, body bit-identical to canonical JSON, signature verifies against `secretCurrent`.

## Layer 3 — Secret rotation job

**Build**

- New `src/jobs/RotateWebhookSecretJob.php`. Activates `secretPrevious = NULL` after the configured grace window (default 24h) since `secretRotatedAt`.
- Console action `password-policy/webhook/rotate-secret <endpointId>` for shell-level rotation (parity with the CP button — operators with CI pipelines can rotate via cron without a CP click).

**Verify**

- Console action rotates secret. After grace window, `secretPrevious` nulls out via the job.

## Layer 4 — CP management surface

**Build**

- New `src/controllers/WebhookEndpointController.php`. Actions: `index` (list view), `edit` (create + edit), `save` (POST), `delete`, `rotateSecret` (AJAX POST), `testFire` (AJAX POST — sends a synthetic audit row to the endpoint and surfaces the response).
- New CP subnav entry `webhooks` under the `Notifications → Activity` neighbour (or `Audit` parent if Phase G adds one — confirm placement during build). Pro-gated isn't enough; this is Enterprise-only — gate on `pp:webhooks-manage` (new permission).
- New `src/templates/_webhooks/_index.twig` + `_edit.twig` matching the patterns from `_notifications/_index.twig` + `_edit.twig` (P1.3). EditableTable for `eventClasses`, secret reveal-on-click + rotate button, last-delivery-status badge per row.
- Console actions `password-policy/webhook/list` and `password-policy/webhook/create --url=... --events=...` ship alongside the CP UI for ops-cron parity (some operators provision endpoints from infrastructure-as-code).

**Verify**

- Visit `/admin/password-policy/webhooks` on Enterprise. Index renders. Create a new endpoint via the CP. Trigger an audit event and confirm the dispatch attempt fires (mock the URL via Mailpit-style local listener for verification).
- Rotate the secret via the CP button. Confirm: `secretPrevious` populated, `secretCurrent` regenerated, grace-window UI surfaces an inline countdown.
- Test-fire button on the edit screen sends a synthetic event and renders the HTTP response inline (status code + first 1KB of body).
- `ddev craft password-policy/webhook/create --url=https://example.com/hook --events=audit_log` works for the IaC path.
- Lite + Pro: subnav doesn't render. Direct URL returns 403.

## Layer 5 — Pest tests

**Build**

- `tests/Integration/Services/WebhookServiceTest.php`. Cover signature generation, replay-attack window enforcement (consumer-side documentation only — the plugin signs; we test signature determinism), secret rotation grace window.
- `tests/Integration/Controllers/WebhookEndpointControllerTest.php`. Cover index render, edit-save round trip, rotate-secret AJAX response shape, test-fire AJAX response, edition gating (Lite/Pro return 403).

**Verify**

- `ddev composer test --filter=Webhook` green.

## Commit

`feat(webhook): HMAC-signed webhook delivery + CP management surface (G9)`

Body: full webhook surface — schema, service, HMAC scheme, secret rotation primitive, CP CRUD, console actions for IaC parity, Pest coverage. How to undo: drop the table + revert the service + remove the controller + console actions + subnav.

---

# G10 — Streaming audit-log export

Extends `AuditController::actionExport` + new `AuditExportJob`.

## Layer 1 — `AuditExportJob`

**Build**

- New `src/jobs/AuditExportJob.php` extending `BaseBatchedJob`. Same pattern as P1.4. `batchSize: 1000`. Per-batch streams to `@runtime/password-policy/exports/<uid>.<format>` via `Craft::$app->getFs($settings->auditExportFilesystem)`.
- Output formats: `csv` and `jsonl`. Header row written on batch 1; subsequent batches append. Final batch closes the stream.
- Fires `EVENT_AUDIT_EXPORT_COMPLETE` (new event class) on completion. Payload: file path, format, row count, requesting admin id.
- Edition-gate via `$plugin->getIsEnterprise()` at execute top.

**Verify**

- Enqueue a job manually. Run queue. Confirm: file produced. CSV opens cleanly; JSONL parses with `jq -s .`.

## Layer 2 — `AuditController::actionExport` rewrite

**Build**

- Synchronous shortcut for small ranges: when `daysFilter < 30 AND row count < 1000`, stream directly via `Craft::$app->getResponse()->stream()`.
- Otherwise: enqueue `AuditExportJob` and respond with `setNotice('Export queued. You will receive an email with the download link when ready.')`. Redirect back to the audit-log index.
- New permission `pp:audit-export`. Register.

**Verify**

- Trigger an export with `--days=7`. Confirm: synchronous stream completes immediately.
- Trigger with `--days=365`. Confirm: queued. Run `queue/run`. File produced. Email arrives in Mailpit with one-time download URL.

## Layer 3 — Filesystem-backed download URL

**Build**

- Use Craft's `\craft\base\FsInterface::createUrl` (or `getRootUrl` + URL composition for filesystems that don't support presigning). Local filesystem = direct file path served via a permission-gated controller action (`AuditController::actionDownload(string $token)`). S3 filesystem = presigned URL.
- One-time-use token via `Craft::$app->getCache()->set("pp:audit-export-token:{$token}", $filePath, 3600)`. Token is consumed on download.

**Verify**

- Click download URL from Mailpit email. File downloads. Click again. 404 (token consumed).

## Layer 4 — Pest tests

**Build**

- `tests/Integration/Jobs/AuditExportJobTest.php`. Cover CSV + JSONL output, batch boundaries, edition gate.

**Verify**

- `ddev composer test --filter=AuditExport` green.

## Commit

`feat(audit): streaming audit-log export via BaseBatchedJob + FsInterface (G10)`

Body: synchronous shortcut + queue-driven mode, JSONL chosen over single mega-array, FsInterface for S3 defense-in-depth, one-time-token download. How to undo: revert the job + the controller diff + the new permission.

---

# G11 — Custom email template paths (Enterprise)

Extends `passwordpolicy_notification_templates` JSON content shape.

## Layer 1 — Content shape extension

**Build**

- No schema migration. Per `feedback_craft5_json_content_pattern.md`, the table already stores `content` as JSON; add `templatePath` as an optional key inside that JSON.
- Update `NotificationTemplateModel`:
  - Add `?string $templatePath` property.
  - Hydrate from the JSON `content` column.
  - Validation rule: `templatePath` must resolve to a readable Twig template file via `Craft::$app->getView()->resolveTemplate()` — fail loudly on save if not found.
- Update `NotificationService::composeFromTemplate`:
  - When `$template->templatePath !== null` AND `$plugin->getIsEnterprise()`, render via `$view->renderTemplate($template->templatePath, $vars)` instead of `renderString($template->body, $vars)`.
  - The rendered body becomes the message body. Subject stays from the DB-stored field (templatePath only swaps body rendering — admins still want to edit subject without touching a Twig template).

**Verify**

- Enterprise: edit a notification template. Set `templatePath = 'emails/breach-detected.twig'` (create the template in the playground site templates dir). Save. Trigger the notification. Confirm: email body comes from the Twig file.

## Layer 2 — Edit-screen UI

**Build**

- Add a "Use Twig template" checkbox + path input on `templates/_notifications/_edit.twig`. Visible only on Enterprise editions (`{% if craft.passwordPolicy.isEnterprise %}` gate). Path field is suggestable via `suggestEnvVars` if the operator wants env-var indirection.

**Verify**

- Enterprise: edit-screen renders the template-path field.
- Pro: edit-screen does NOT render the field.

## Layer 3 — Edition strip on save

**Build**

- In `NotificationTemplateController::actionSave`, unconditionally `unset($content['templatePath'])` when `!$plugin->getIsEnterprise()`. **In the same commit.** Defense-in-depth.

**Verify**

- Switch to Pro. Crafted POST with `content[templatePath] = 'malicious.twig'`. Save. Inspect DB JSON content — `templatePath` not present. (Defense-in-depth holds.)

## Layer 4 — Pest tests

**Build**

- `tests/Integration/Services/NotificationServiceTemplatePathTest.php`. Cover: Enterprise rendering path, Pro strip-on-save, missing-template validation.

**Verify**

- `ddev composer test --filter=TemplatePath` green.

## Commit

`feat(notifications): Enterprise custom email template paths via Twig file (G11)`

Body: extends the JSON content shape, edition-strip defense-in-depth, validation contract (file must resolve), why subject stays DB-stored even when body uses templatePath. Maps to whitelabeling / brand-enforcement use case. How to undo: drop the property + the strip + revert composeFromTemplate.

---

# G12 — Enterprise notification keys (`new-device-alert`, `admin-security-alert`)

Move both from `composeFromKey` (mailer-templates.php) source to the editable-templates surface. F2's `_dispatchMailerKey` path retires for these two types.

## Layer 1 — EmailDefaults seed migration

**Build**

- Generate via `ddev craft migrate/create AddEnterpriseNotificationDefaults --plugin=password-policy`.
- Migration body: for each enabled site, insert rows in `passwordpolicy_notification_templates` for `new-device-alert` + `admin-security-alert` keys with default content from new methods on `EmailDefaults` (`EmailDefaults::newDeviceAlert()` + `EmailDefaults::adminSecurityAlert()`).
- Idempotent guard: skip if rows already exist for the (key, siteId) tuple.
- Update `Install.php::_seedNotificationTemplateDefaults()` to mirror.

**Verify**

- `ddev craft migrate/up --plugin=password-policy` succeeds. Inspect `passwordpolicy_notification_templates` — new rows for both keys per enabled site.

## Layer 2 — `NotificationService` upgrade

**Build**

- Replace `sendNewDeviceAlert()`'s `_dispatchMailerKey` path with `_dispatch()` — full subject + body capture. Pass `deviceLabel` + `maskedIp` as `extraVars`.
- Replace `sendAdminSecurityAlert()`'s `_dispatchMailerKey` path similarly. Pass `event` + `context` as `extraVars`.
- Both now flow through `composeFromTemplate()` + the F2 capture invariant (rows on success and failure).
- Update `_templateKeyForType()` to resolve the new keys: `'new_device' => 'new-device-alert'`, `'admin_alert_*' => 'admin-security-alert'` (note the wildcard match — admin alerts share one template across all event subtypes; the `event` Twig variable distinguishes).

**Verify**

- Trigger a new-device alert. Confirm: row in notification_log with `subject` + `body` populated. Email content matches DB template.
- Trigger admin alerts for several event subtypes. Confirm: all use the same template, but `{event}` token varies in the rendered output.

## Layer 3 — CP edit-screen support

**Build**

- The existing `NotificationTemplateController::actionEdit` already handles per-key editing — both new keys appear automatically in the index.
- Add token-picker chips for the new keys' template variables: `deviceLabel`, `maskedIp`, `event`, `context.userId`, etc.

**Verify**

- Visit `/admin/password-policy/notifications`. Confirm: `new-device-alert` + `admin-security-alert` listed alongside `expiry-reminder` and `breach-detected`.
- Edit each. Token-picker chips render. Save round-trips.

## Layer 4 — Resend support

**Build**

- Update `_templateKeyForType()` to make these types resendable. The resend path was previously gated on editable-template-driven types only — now both new types qualify.
- Add `extraVars` resolution for the resend path (re-derive `deviceLabel` / `maskedIp` from the original `notification_log` row's stored payload — F2's `body` column captures the rendered output but not the input vars; we add a new nullable `templateVarsJson` column to the notification_log table to capture inputs at dispatch time and replay them on resend).
  - Wait. This deserves architectural attention. F2 doesn't snapshot input vars; it snapshots rendered output. Resending `new-device-alert` requires knowing the original `deviceLabel`. Two options: (a) add `templateVarsJson` column, (b) refuse to resend on these types and document. Option (a) preserves the resend UX consistency; option (b) is simpler but inconsistent.
  - **Decision: option (a).** Add nullable `templateVarsJson` to `passwordpolicy_notification_log` via a new migration in this layer. Captures inputs alongside outputs. Resend path reads `templateVarsJson` and re-renders with the same inputs against the current template (admin may have edited template since the original send — fresh render still applies).
- Generate the migration: `ddev craft migrate/create AddTemplateVarsToNotificationLog --plugin=password-policy`. Idempotent column add. Bump schema version.

**Verify**

- Trigger a new-device alert. Inspect notification_log — `templateVarsJson` populated.
- Resend it via the activity panel. Confirm: re-renders cleanly with the same `deviceLabel`.

## Layer 5 — Pest tests

**Build**

- `tests/Integration/Services/NotificationServiceEnterpriseKeysTest.php`. Cover both new keys' dispatch paths (success + failure capture), edit-screen round-trip, resend flow with `templateVarsJson` replay.

**Verify**

- `ddev composer test --filter=EnterpriseKeys` green.
- Existing F2 tests (`NotificationServiceCaptureTest`, `NotificationServiceResendTest`, `NotificationActivityServiceTest`) continue to pass.

## Commit

`feat(notifications): Enterprise notification keys move to editable-templates surface (G12)`

Body: migration adds two seed rows per site, NotificationService rewrites the two dispatch paths to flow through composeFromTemplate (full capture instead of mailer-key shim), templateVarsJson column added for resend replay. How to undo: revert the migrations + restore _dispatchMailerKey for these two keys.

---

# Phase G event additions

For `docs/user/reference/events.md` — add rows in the same commit as each layer that introduces them.

| Event | Class | Edition | Phase G layer |
|---|---|---|---|
| `EVENT_AUDIT_CHAIN_ROTATED` | `events\AuditChainRotatedEvent` | Enterprise (capture every; payload exposed Enterprise-only via the dashboard) | G1 layer 5 |
| `EVENT_POLICY_CHANGED` | reuses `events\PolicyChangedEvent` if present, otherwise new in G4 | Lite (capture every per project_audit_capture_principle; consumed Enterprise) | G4 layer 2 |
| `EVENT_ALERT_COOLDOWN_FIRED` | `events\AlertCooldownEvent` | every edition (capture surface) | G7 layer 2 |
| `EVENT_SIEM_FORWARD_ATTEMPT` | `events\SiemForwardAttemptEvent` | Enterprise | G8 layer 3 |
| `EVENT_WEBHOOK_DELIVERY_ATTEMPT` | `events\WebhookDeliveryAttemptEvent` | Enterprise | G9 layer 2 |
| `EVENT_AUDIT_EXPORT_COMPLETE` | `events\AuditExportCompleteEvent` | Enterprise | G10 layer 1 |

---

# Hard guards (read MEMORY.md too)

- **Always** generate migrations via `ddev craft migrate/create <Name> --plugin=password-policy`. Never hand-pick filenames or timestamps.
- **Use ddev shorthand commands.** Never `php`, `composer`, or `npm` on the host.
- **PHPDocs on every class + public method** — `@author CraftPulse` + `@since 5.2.0`. Section headers with `// =========================================================================` separators. Non-negotiable.
- **No commit AI attribution.** No `Co-Authored-By` trailers. No "Claude" / "Claude Code" / "AI" mentions.
- **Capture is universal.** The hash chain runs on Lite. Edition gates apply to verifier UI, dashboard, forwarder, webhook, export — never the underlying writes.
- **New Pro / Enterprise setting keys MUST be added to `SettingsController::actionSave`'s strip block in the same commit.**
- **Don't relitigate decisions in `audit-logging.md` (a)–(f).** Lock them. This plan is implementation-level architecture on top of those locks.
- **Default to native Craft components.** `forms.editableTableField` for admin-managed lists; `<blockquote class="note tip|warning">` for high-visibility callouts; `|datetime`/`|time` for locale-aware timestamps.
- **No new composer dependencies in 5.2.0** unless explicitly approved. Phase G's syslog-over-TLS uses raw `stream_socket_client` — no Guzzle dependency for that path. Webhook signing reuses Guzzle (already in the require). If a SIEM library would simplify (e.g. `monolog/monolog`'s syslog handler), flag with `(needs approval)` before pulling.
- **Privacy guardrails on hash chain.** The canonical payload contains `userIdentifier` (HMAC) and `ipHash` (SHA-256) — never raw email or raw IP. Never log the canonical payload at debug level (it would render the chain tamper-detection useless if any attacker reads logs and reconstructs the canonical string). Add a privacy comment in `AuditLogService::canonicalize()`.
- **Twig errors propagate naturally** for the dashboard + report templates. Don't wrap renders in defensive try/catch — surface them via Craft's normal error path.
- **Edition gating is graceful, not throwing**, for read-side surfaces (dashboard, reports, forwarders index). Pro users either don't see the subnav or get a 403 from the controller's `requirePermission` — never a `\RuntimeException`. Throwing is reserved for service-layer entry points where a Pro caller hitting an Enterprise-only method is a defect (e.g. `WebhookService::dispatch` should throw on Pro because no caller should reach there).

---

# Commit protocol

- Commit at the end of each verified layer. Roughly 40–50 commits total for Phase G (G1: 5 layers, G2: 3, G3: 5, G4: 3, G5: 3, G6: 3, G7: 5, G8: 6, G9: 5, G10: 4, G11: 4, G12: 5 = 51 layer-commits if every layer commits separately; some layers may fold).
- Conventional commit prefixes: `feat`, `refactor`, `test`, `docs`, `chore`. Match the existing log style.
- Imperative mood. Extensive bodies covering *why* + *what* + *how to undo* + subtle gotchas. Match `7b9d7b7` (UX polish) and `04178bf` (P1.4 batched job).
- DO NOT push. Local commits only — user pushes on their own cadence.
- HEREDOC commit messages for proper formatting.

---

# Final deliverables

When Phase G is complete:

- **Files created:** ~40-50 new files across events, services, records, jobs, controllers, migrations, templates, console controllers, utilities, and Pest tests.
- **Files modified:** `src/PasswordPolicy.php`, `src/services/ServicesTrait.php`, `src/services/NotificationService.php`, `src/services/AuditLogService.php`, `src/migrations/Install.php`, `src/data/EmailDefaults.php`, `src/models/SettingsModel.php`, `src/controllers/SettingsController.php`, `src/templates/_notifications/_edit.twig`, `composer.json` (only if a new dep gets approved — otherwise unchanged).
- **manual-tests.md:** ~25-30 new T-row entries across T14.x (audit chain) → T19.x (Enterprise notification keys).
- **plan.md:** strike P3 Phase 10/11/12 + the two Phase G additions. Mark Phase G done. Phase H becomes next.
- **handover.md:** refresh for Phase H start (release prep + deployment docs + Plugin Store listing).
- **CHANGELOG.md:** entries for all 12 G items under `[5.2.0] - Unreleased`.
- **`docs/user/reference/events.md`:** five new event rows.
- **`docs/user/features/audit-logging.md`:** sections (a)–(f) marked DONE; new section "Webhook delivery" documenting the consumer-side scheme (HMAC verification, replay window, idempotency UUID, secret rotation).
- **Suite:** target ~700 passing / ~1500 assertions. Phase E + D + F2 tests continue to pass; Phase G adds ~150 new tests.
- **Working tree clean** after Phase G completion.

---

# Reporting

When complete, report:
- Files created (count + grouped by feature)
- Files modified (count + list)
- Commits made (count + one-liner each)
- Verify steps that revealed issues + how they were resolved
- Architectural assumptions made that weren't explicit in the plan (with rationale)
- What's left for the user to verify manually (browser-only UX, multi-site fixtures we don't have on the playground, real syslog/webhook endpoints)
- Skill gaps surfaced during the build (every Craft API gotcha, every "how does X work in Craft 5" question that took >10 minutes to answer)

If a verify step fails and you can't recover, STOP and report. Don't push past failures. Surface the issue with file path + line number + expected vs actual.

---

# Scope decisions — what ships in 5.2.0 vs defers to 5.3 vs not adopted

User-confirmed on 2026-05-06. The original draft proposed deferring G9's CP management UI to 5.3 alongside the REST surface. That was reviewed and reversed: half-shipping G9 (infrastructure without the CP CRUD) was rejected as creating a "you have webhooks but can't make one without a console" gap. G9 ships in full. syslog UDP was reviewed and dropped from the matrix entirely (not parked, not deferred — cut) since UDP is unreliable for audit forwarding and no buyer profile asks for it. Phase 12 REST stays deferred — it's a substantial feature on its own and G10 streaming export covers the machine-readable-audit need for 5.2.0.

**Ships in 5.2.0:**

| ID | Item | Rationale |
|---|---|---|
| G1 | Audit hash chain | Compliance positioning depends on this. Trails differentiator. |
| G2 | Verifier CLI | Hash chain without an open-source verifier is just marketing. |
| G3 | Compliance dashboard + reports | Visible Enterprise UI; the buyer sees this at evaluation. |
| G4 | Field-level diffs on policy changes | Direct ISO 27002 A.5.37 + SOC 2 CC8.1 evidence. |
| G5 | Per-event PII allowlist | Privacy-by-design USP made auditable. |
| G6 | Per-policy custom blocklist | Specops-style differentiator. Schema column already shipped at install. |
| G7 | AlertCooldownService | F2's existing dedup is uncomfortable to leave un-factored. The G8 forwarder needs the cooldown for circuit breaker. |
| G8 | SIEM syslog-over-TLS | Regulated-industry buyers already speak this protocol. |
| G9 | Webhook forwarder (full surface) | Schema + service + HMAC + secret rotation + CP management UI + endpoint CRUD + console parity. Ships whole. |
| G10 | Streaming audit-log export | SOC 2 / NIS2 evidence packages need 12+ months of audit-log data without PHP memory ceiling. Also covers the machine-readable-audit need that REST would otherwise serve. |
| G11 | Custom email template paths | Whitelabeling for Enterprise; small surface, high perceived value. |
| G12 | Enterprise notification keys | Closes the F2 capture-coverage gap (`new_device` + `admin_alert_*` currently lack subject/body capture). |

**Deferred to 5.3:**

| ID | Item | Rationale |
|---|---|---|
| Phase 12 § REST | ApiTokenService + ApiController REST surface | Substantial layer on its own — token storage, scopes, per-token rate limiting, full CRUD surface, OpenAPI surface, auth middleware. G10's streaming export covers the batch-import-to-SIEM use case in 5.2.0. The REST is interactive-only and earns a 5.3 placement on its own merits. |

**Not adopted (rejected outright; preserved here so future planning doesn't reopen):**

- syslog UDP forwarder protocol — UDP is unreliable for audit forwarding, TCP/TLS is the compliance-correct default; no buyer profile asks for it. Cut from the matrix, not parked.
- RFC 3161 external timestamping
- AWS S3 Object Lock anchoring
- GeoIP enrichment on audit rows
- Splunk HEC / Datadog destinations as native protocols (operators integrate via syslog forwarder or webhook — both already present)
- Merkle tree hash batching (volume doesn't justify; flat per-row chain is simpler to verify)

---

Files referenced in this plan (absolute paths):

- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/src/services/AuditLogService.php`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/src/services/NotificationService.php`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/src/jobs/SendPasswordExpiryRemindersJob.php`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/src/migrations/Install.php`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/docs/user/features/audit-logging.md`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/docs/user/reference/events.md`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/docs/internal/plan.md`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/docs/internal/handover.md`
- `/Users/michtio/dev/craft-plugins/v5/craft-password-policy/docs/internal/history/phase-c2-build-plan.md` (structural template)