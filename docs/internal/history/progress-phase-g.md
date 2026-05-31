# Phase G — Enterprise build (closed 2026-05-14)

G1–G12 + post-review remediation Steps 1–8. Twelve features across 17K+ lines, three record→element refactors, eight remediation steps. Pest suite went 551 → 786 passing / 0 skipped (1875 assertions). ECS + PHPStan clean. Schema version landed at 2.11.0.

The cumulative session range is `cf3e2f1` (G1 — `feat(audit): hash-chained audit log infrastructure`) through `be33546` (G3 — `feat(compliance): dashboard utility + aggregate service + HTML/CSV report controller`).

**Foundation-first principle held throughout.** Three record→element refactors (NotificationLog, AuditLog, Policy) landed before downstream features so user data never carries 5.2.0 → 5.3 migration debt. Per `feedback_foundation_first_no_refactor_deferrals.md`: only deferrals that build ON 5.2.0 go to 5.3+; never major refactors of shipped surfaces.

## Initial G1–G9 build pass (2026-05-07 → 2026-05-10)

Layered execution against the F3 build plan. Each feature took roughly one focused session; the chain was:

- **G1 — hash-chained audit log infrastructure.** SHA-256 forward chain. Canonical JSON (alphabetical key order + UTC ISO 8601 + first-row sentinel `'0' × 64`). New `rowHash` + `previousHash` columns on `passwordpolicy_audit_log`. `AuditLogService::canonicalize()` produces bit-identical bytes from any row. Migration `m260507_081201_AddRowHashAndPreviousHashToAuditLog` adds the columns; `m260507_081852_RecomputeAuditLogChain` walks pre-existing rows and back-fills `rowHash` chained from a synthetic genesis.
- **G2 — verifier CLI.** `password-policy/audit/verify` chain-walk. Exit codes `0` (valid) / `1` (first break) / `2` (schema drift). JSON-emit mode for CI. Retention-purge-tolerant — partial chains exit `0` with notice.
- **G3 — compliance dashboard utility + aggregate service + HTML/CSV reports.** (Originally G3, deferred to Step 8b — see remediation below).
- **G4 — policy-change diffs.** Field-level before/after diffs captured into `AuditLogService::logEvent()` when admins edit named policies. Structured JSON allowlist via `ALLOWED_DETAILS_BY_EVENT`. Maps to ISO 27002 A.5.37 + SOC 2 CC8.1 change-management evidence.
- **G5 — PII allowlist.** Per-event-class allowlist registered in `ALLOWED_DETAILS_BY_EVENT`. Fails closed: unrecognised keys silently dropped before write. Inspectable per-event config for auditors.
- **G6 — per-policy custom blocklist editor.** The Pro `BlocklistService::addCustomWord()` schema column `policyId` shipped in P1.11 — G6 added the Enterprise editor tab on the policy edit screen and merged per-policy entries via `CommonPasswordValidator` against the user's resolved policy set.
- **G7 — `AlertCooldownService` + `passwordpolicy_alert_cooldowns` table.** Generalises F2's dedup pattern per-event-class. Migration `m260507_122940_AddAlertCooldownsTable`. Replaces ad-hoc throttling on HIBP-on-login mass detections, group-deletion cascades, force-reset bursts.
- **G8 — syslog-over-TLS SIEM forwarder.** `SiemForwarder` model + `SiemForwarderRecord` + `SiemForwarderController` + `SiemService` + `SiemForwardJob` (`BaseBatchedJob`-driven). Non-transparent newline framing (RFC 6587 §3.4.1). Migration `m260507_132250_AddSiemForwardersTable`. Splunk HEC + Datadog Logs + any RFC 5424 receiver verified during build.
- **G9 — webhook forwarder full surface.** `WebhookEndpoint` model + `WebhookEndpointRecord` + `WebhookEndpointController` + `WebhookService` + `WebhookForwardJob`. `X-PasswordPolicy-Signature: sha256=<hex>` HMAC. 5-minute replay window. Idempotency UUID. Secret rotation flow. Migration `m260507_175059_AddWebhookEndpointsTable`.

At G9 close: 9 commits, suite at 713 / 1618.

## Post-review remediation Steps 1–8 (2026-05-08 → 2026-05-14)

Code review across G1–G9 surfaced 9 verified issues + 1 false positive (reviewer claimed `AuditExportCompleteEvent` was missing from `events.md`; it's at line 402). Each finding manually verified against the cited `file:line` before the remediation chain landed.

### Step 1 — Bundled fix-pack (`4ca1c0a`, 2026-05-08)

C1, C2, C3, I1, I2 — ~80 lines, zero new functionality.

| ID | File:line | Fix |
|---|---|---|
| C1 | `SiemForwardJob.php:282-288` | `_recordRowOutcome()` catch swapped `throw new RuntimeException` for `Craft::error()` + `return`. Method's docblock declares "best-effort, never rethrown" — pre-fix violation caused duplicate SIEM forwarding on retry. |
| C2 | `AuditController.php:870` and `:262` | `$query->all()` → `->batch(1000)` cursor. Production-scale audit logs OOM under `->all()`. |
| C3 | `AuditExportController.php:306-327` | Closure-as-stream pattern dropped. Now `return $this->asRaw($payload)` with explicit `Content-Type` + `Content-Disposition` headers. Memory budget at the 1000-row sync threshold is fine. Closure had been returning `[true, true]` instead of `[string $data, bool $finished]`, so Yii echoed a stray `"1"` after the payload. |
| I1 | `AuditLogService.php:161,172`; `AuditController.php:67,76`; `m260507_081852_RecomputeAuditLogChain.php:61,79` | `GENESIS_PREVIOUS_HASH` + `CANONICAL_DATE_FORMAT` promoted from triplicated `private const` to single `public const` on `AuditLogService`. Drift between the three sites would silently invalidate every chain hash without test or static-analysis signal. |
| I2 | `PolicyService.php:270` | `new \DateTime()` → `Carbon::now('UTC')->format('Y-m-d H:i:s')`. Server-local TZ on non-UTC servers stamped wrong; every other datetime write in the codebase already uses Carbon UTC. |

### Step 2 — Dedicated `CRAFT_AUDIT_PII_KEY` + CLI generator (`dc5bbd1`, 2026-05-09)

I5 — `AuditLogService::_hashUserIdentifier()` had been using `Craft::$app->getConfig()->getGeneral()->securityKey` as the HMAC secret. The privacy USP framing — "rotating the audit-PII key destroys historical correlation without breaking site security" — was not currently true; rotating `securityKey` also breaks session signing, security tokens, etc.

**Choice (a)** taken: dedicated `auditPiiKey` added to `SettingsModel` + `config/password-policy.php`. Independent of `securityKey`. New CLI generator at `password-policy/audit/generate-pii-key` outputs a 64-character random hex. Operator docs added in `docs/user/operations/upgrade-from-5.1.md`. Key rotation documented as a privacy lever.

### Step 3 — Verify-then-decide pass on I4, I7, N1–N6 (`87149dd`, 2026-05-10)

Eight reviewer claims verified inline against current code. Decisions per claim:

| ID | Decision | Action |
|---|---|---|
| I4 | Real (SIEM/Webhook `sendTestEvent()` race — `logEvent()` then `ORDER BY id DESC LIMIT 1` could pick a stale row). | `logEvent()` now returns the new row id. |
| I6 | Real but non-blocker (SIEM uses non-transparent newline framing; interop concern only; no embedded LFs in plugin-emitted RFC 5424 frames). | Parked to `ideas.md` "RFC 6587 octet-count framing as opt-in." Worth half-day work post-5.2.0. |
| I7 | Real (`SiemForwarderController::actionSendTest()` exposed raw `$e->getMessage()`). | Generic error string + log-the-exception pattern applied. |
| N1 | False (docblock-code mismatch on a cache that didn't exist). | Docblock removed. |
| N2 | Real (IPv4 hashed without HMAC). | Switched to HMAC with `auditPiiKey`. |
| N3 | Real (`RotateWebhookSecretJob` warning on null). | Defensive null guard. |
| N4 | Real (BlocklistService TOCTOU). | Lock-on-write pattern applied. |
| N5 | Real (permission flat-vs-nested convention drift). | Audited; aligned with `architecture.md` convention. |
| N6 | Real (AuditExportController filename regenerated at serve time). | Stable filename pinned at token-issue time. |

### Step 4 — `NotificationLogRecord` → `NotificationLogElement` (`2d0144e`, 2026-05-10)

Foundation refactor #1. Per `feedback_foundation_first_no_refactor_deferrals.md`, record-to-element conversions ship in 5.2.0 because the post-release migration cost is severe.

- Schema rewrites `passwordpolicy_notification_log.id` to FK `craft_elements.id` (CASCADE delete). Migration `m260511_133103_ConvertNotificationLogToElement`.
- New `NotificationLogElement` + `NotificationLogQuery` + element actions (Resend, Delete, Restore).
- `NotificationActivityController` index swaps to native element-index rendering; per-user panel switches to `NotificationLogElement::find()`.
- `NotificationService::_logNotification` and `resend()` adapt to the element surface.
- Schema bump 2.8.0 → 2.9.0.

Playground test data was truncated by the migration (unreleased; documented in migration body).

### Step 5 — `AuditLogRecord` → `AuditLogElement` (`ba520a5`, 2026-05-11)

Foundation refactor #2. Same pattern as Step 4 but on the bigger audit-chain surface.

- Migration `m260511_154624_ConvertAuditLogToElement`.
- Element actions: View detail, Export selection, Delete (admin override only).
- Element-delete cooperates with retention purge (`EVENT_AUDIT_CHAIN_ROTATED` still fires; element soft-delete via `dateDeleted` is the new boundary).
- Chain hash computed from element-record content unchanged — `canonicalize()` continues to produce bit-identical bytes.
- `password-policy/audit/verify` console command continues to walk via the existing query (element layer is purely additive).
- Schema bump 2.9.0 → 2.10.0.

### FK dedup follow-up (`f800d72`, 2026-05-11)

Steps 4 + 5 left duplicate foreign keys on the rewritten tables — both the legacy FKs from the original Install.php and the new element FKs survived the migration. `fix(audit,notifications): dedupe foreign keys left over from element conversion` drops the legacy FKs after verifying the element FKs do the job. Schema unchanged.

### Step 6 — `PolicyRecord` → `PolicyElement` (`2809614`, 2026-05-13)

Foundation refactor #3. Same pattern. Project-config-sync interaction was the wrinkle — solved by treating policies as project-config-driven elements (config writes drive element saves, element saves don't write back to config).

- Migration `m260513_172440_ConvertPolicyToElement`.
- Element actions: Edit, Delete.
- `PolicyService::saveFromConfig()` rewrites to `$element = PolicyElement::findOne(['uid' => $uid]) ?? new PolicyElement(); ... $element->setScenario(...); $element->save()`.
- Resolver path unchanged — `PolicyResolverService::resolveForUser()` still queries via `PolicyQuery`.
- Schema bump 2.10.0 → 2.11.0.

### Step 7 — G12 mailer-key regression resolution (`ede5071`, 2026-05-13)

Moved `password-policy:new-device-alert` + `password-policy:admin-security-alert` keys from `composeFromKey()` (mailer-templates path) to `_dispatch()` (editable-templates path). Per-site DB-stored seeds via `EmailDefaults::all()`. `_dispatchMailerKey()` deleted. `composeFromTemplate()` widened to `?User` for admin-alert mode.

Resend for these two types is deferred until 5.3+ adds a `templateVarsJson` column. Additive future work, foundation-positive.

### Step 8a — G11 Enterprise custom email template paths (`fd2c806`, 2026-05-14)

Optional "use Twig template" override mode on each notification template. Admin specifies a path (e.g. `_emails/expiry-reminder.twig`); plugin renders that file instead of the DB-stored body. Schema: nullable `templatePath` field added to the JSON `content` shape on `passwordpolicy_notification_templates`. Edition strip on save prevents Pro from writing template paths.

Whitelabeling / brand-enforcement use case for Enterprise customers who want version-controlled, dev-managed templates with full HTML support. Multi-site framing already handled in 5.2.0 by per-site rows; this is the dev-managed-template lever on top.

### Step 8b — G3 compliance dashboard + reports (`be33546`, 2026-05-14)

Final commit of Phase G.

- `ComplianceDashboardUtility` (aggregates) — Enterprise CP utility surfacing population-wide metrics: HIBP-detected breach exposure, expired-password counts, force-reset queue depth, audit-chain integrity.
- `ComplianceAggregateService` — read-only service computing dashboard aggregates via SUM/COUNT queries. Cached for 5 minutes.
- `ReportController` — generates HTML + CSV reports anchored to NIS2, NIST 800-63B Rev 4, PCI DSS v4.0.1, ISO 27001:2022, SOC 2 framework clauses. Per `project_compliance_positioning.md`.
- Framework anchors via `docs/user/operations/compliance-frameworks.md`.

Plan-doc rollup committed in `5c2e954` (`docs(plan): close Phase G — G1–G12 all shipped, Phase H unblocked`) and `dfd656b` (`docs(plan): correct stale 5.1.x state — 5.1.2 shipped 2026-05-02`).

## Cumulative metrics at Phase G close

- **Suite:** 786 passing / 0 skipped / 1875 assertions (+235 over Phase F close).
- **Schema:** 2.11.0 (G1: 2.4.0 → 2.5.0; G7: 2.5.0 → 2.6.0; G8: 2.6.0 → 2.7.0; G9: 2.7.0 → 2.8.0; Step 4: 2.8.0 → 2.9.0; Step 5: 2.9.0 → 2.10.0; Step 6: 2.10.0 → 2.11.0).
- **ECS + PHPStan:** clean, PHPStan baseline unchanged.
- **New tables:** `passwordpolicy_alert_cooldowns`, `passwordpolicy_siem_forwarders`, `passwordpolicy_webhook_endpoints`.
- **Element-ified tables:** `passwordpolicy_notification_log`, `passwordpolicy_audit_log`, `passwordpolicy_policies` (all FKed to `craft_elements.id` CASCADE).
- **Commits:** session range `cf3e2f1` → `be33546`. 

## Skill-gap learnings from Phase G review

Four new entries captured outside `MEMORY.md` in the user's personal skill files:

1. **Shared constants public-not-private.** Constants referenced from more than one site MUST live on a `public const` on the canonical owning class. Triplication is a chain-invalidation footgun.
2. **Queue job best-effort rethrow contract.** When a method's docblock declares "best-effort, never rethrown", the catch block MUST swap any throw for log+return. Otherwise the contract is silently violated and retries duplicate.
3. **HMAC vs bare hash for PII.** PII correlation hashes need an HMAC with a dedicated key, NOT `hash('sha256', $pii)`. Otherwise rainbow-table attacks recover the PII. Dedicated key separately from `securityKey` so rotation doesn't break sessions.
4. **Yii `Response::$stream` callable signature.** Returns `[string $data, bool $finished]`. `[true, true]` produces a stray `"1"` after the payload because Yii string-casts `true` to `"1"`.

## What's next (post-Phase G)

Phase H release prep. Tag 5.2.0, Plugin Store listing, marketing copy, migration guide review, deployment/cron docs, **Enterprise QA pass** (T12.6 + new T14.x–T22.x rows for every Phase G surface).

In practice between Phase G close and Phase H tag, two additional arcs of work landed: the security audit polish bundles + the Phase 2 edition realignment. See [`progress-phase-h-prep.md`](./progress-phase-h-prep.md).
