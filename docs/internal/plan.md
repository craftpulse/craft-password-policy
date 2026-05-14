---
title: Password Policy v5.2.0 — Master Plan
version: 5.2.0
branch: 5.x
last_updated: 2026-05-14
status:
  pro_ui: feature_complete
  pest_suite: 786 passing / 0 skipped / 1875 assertions
  manual_tests: 78/79 PASS active pass; T1.2 + TX.2 + T9.7 now covered by Pest (E6); T12.6 + T13.6 + T13.11 + Phase G T-rows pending Enterprise QA
  p1_remaining: 0
  p2_remaining: 0 (P2.1 + P2.2 done as Phase D; P2.4 absorbed into P1.12; P2.5 done as Phase E; P2.6 absorbed into Phase D verification gate; P2.8 drafted 2026-05-06 → phase-g-build-plan.md; P2.9 done as Phase F2 2026-05-06)
  enterprise: phase_g_complete (G1–G12 shipped on `5.x`)
  bug_fix_sweep_2026_05_02: 11_bugs_landed_zero_pest_coverage_now_pinned_by_E4_E5
release_strategy: single_5_2_0_includes_all_editions (5.1.x maintenance line shipped 5.1.2 on 2026-05-02 — tag + push complete; channel idle until a new security signal arrives)
gate: phase_h_release_prep_ready_to_start
read_order_active: [1, 2, 3, 4]
companion: reference.md (sections 5–7 — completed work, architecture decisions, source-code inventory)
---

# Password Policy v5.2.0 — Master Plan

Master plan for the v5.2.0 Pro/Enterprise expansion. Sections 1–4 cover active work and live in this file.

Reference material — completed work history, settled architecture decisions, and source-code inventory — lives in the companion file [`reference.md`](./reference.md). Skip the reference unless investigating prior context.

## Contents

| # | Section | State |
|---|---|---|
| 1 | [Status](#1-status) | active |
| 2 | [Manual testing remaining](#2-manual-testing-remaining) | active — 78/79 PASS; T1.2 + TX.2 + T9.7 covered by Pest (E6); P2.1/P2.2/P2.6 covered by Pest (D); T12.6 + T13.6 + T13.11 require Enterprise/browser/SR gates |
| 3 | [Backlog](#3-backlog) | active |
| 4 | [Build order](#4-build-order) | active |
| — | [Reference (completed work, architecture, inventory)](./reference.md) | done, skippable |

State legend: `active` = read now, `pending` = scheduled, `done` = built, `blocked` = gated, `settled` = decided.

---

## 1. Status

- **Phase D closed 2026-05-03.** 19 commits (D0 audit context surface; D1 audit listener wiring; D2 user-index columns + condition rules; D3 admin element actions + UserPasswordController; D4 user-edit "tab" via sidebar pointer + UserSecurityController). **Pest suite: 513 passing / 0 skipped / 1049 assertions** (+184 over Phase E). ECS clean, PHPStan clean (3-entry baseline unchanged). Three new D-cycle follow-ups codified in `ideas.md`. P2.6 verification gate satisfied throughout — every new CP affordance respects `allowAdminChanges = false`. Phase D session log: `history/progress-phase-d.md`.
- **Phase E closed 2026-05-02.** 18 commits (E1 bootstrap + HibpClient extraction; E2 pure validators; E3 DB-touching services + factories; E4 HIBP backoff + StrengthService + SettingsModel alias; E5 ValidationController + destroyOtherSessions + PasswordWidgetTag; E6 migration replay + multi-site propagation + FK CASCADE) plus a `fix(hibp)` log-level downgrade and a `docs(ideas)` cleanup-candidates capture. All three deferred manual tests (T1.2, TX.2, T9.7) now covered by Pest. The C2 bug-fix sweep is pinned by 32 of E4+E5's tests. Phase E session log: `history/progress-phase-e.md`.
- **Phase C2 closed-closed 2026-05-02.** P1.12–P1.15 shipped, plus the 11-bug code-review sweep landed (commits `322c18f` → `9691541`). Pro front-end Twig surface is now the largest single feature in the plugin.
- **Phase F UI sweep landed 2026-05-06.** Single commit `refactor(users): polish user-edit UI sweep — status pills, edit-screen event, action menu`. User-index renderers rewritten with `Cp::statusLabelHtml()` + `Color` enum + empty-cell convention; expiry-dependent columns + sort options gated on `expiryAmount` configured; `_registerUserEditTab()` (sidebar pointer workaround) replaced with a real `UsersController::EVENT_DEFINE_EDIT_SCREENS` registration (memory gap #21 corrected — the event ships in Craft 5.0+, contrary to an earlier wrong-as-stated claim); `Element::EVENT_DEFINE_ACTION_MENU_ITEMS` listener appends Force Reset / Send Reset Email / Change Password… to the per-user edit screen "…" menu; `ChangeUserPassword` dropped from index bulk-action menu (same-password-on-N-users is a security anti-pattern) — class kept for the static modal helpers consumed by the action menu listener, dead `getTriggerHtml()` override removed; modal styling pinned (480px + `fitted`) and wrapped in `Craft.elevatedSessionManager.requireElevatedSession()`; `UserSecurityController` switched to `EditUserTrait` so the left nav stays visible. Quiet correctness bug surfaced + fixed: `UserQuery` selects neither `lastPasswordChangeDate` nor `passwordResetRequired` — the latter newly verified — so the "Password reset has been requested" banner never rendered and the Force Password Reset button always showed; both columns now hydrate via direct scalar query in `UserSecurityController::actionIndex()`. Memory `feedback_skill_gaps.md` updated — gap #21 corrected, #22 added (status pill helper), #23 added (action menu vs index actions duality).
- **Phase F2 notifications activity surface landed 2026-05-06.** Single commit `feat(notifications): activity surface — capture-on-failure + resend + per-user panel`. `passwordpolicy_notification_log` schema-rewrites into a real audit table (`status` + `recipientEmail` + `siteId` + rendered `subject`/`body` + `errorMessage` + `resentFromId`); idempotent migration `m260506_174529_AddNotificationLogActivityColumns`; `Install.php` matched; `schemaVersion` 2.3.0 → 2.4.0. `NotificationService` rewrites the row write OUT of the success try block — both success and failure paths capture rows; `Throwable::getMessage()` on the failure path lands in `errorMessage`; `composeFromTemplate()` exposes a `&$rendered` out-param so the dispatch path captures rendered subject + body without a redundant second `View::renderString()` pass. Dedup gate `_hasRecentNotification()` filters on `status = 'sent'` so failed-then-retried doesn't suppress. New `NotificationService::resend(NotificationLogRecord)` re-renders fresh from the current template (NOT snapshot replay), bypasses dedup, chains via `resentFromId`, rejects non-resendable mailer-key types. New `NotificationActivityService` (read-side), `NotificationActivityController`, URL rules, `Notifications → Activity` sibling subnav. Per-user notifications panel embedded on the Password Security screen. New `NotificationStatus` backed enum (Sent / Failed). Notification-log GC pruner ungated from Pro (architectural fix — capture runs on every edition per `project_audit_capture_principle.md`, so prune must too). Three Pest test files added: `NotificationServiceCaptureTest`, `NotificationServiceResendTest`, `NotificationActivityServiceTest`. Bounce ingestion (provider webhooks) deferred to `ideas.md`. **Suite at 551 passing / 0 skipped / 1151 assertions.** P2.9 closed.
- **P2.8 drafted 2026-05-06 → [`internal/phase-g-build-plan.md`](./phase-g-build-plan.md); scope confirmed 2026-05-06.** Layered build plan, twelve features G1–G12, locked architecture (SHA-256 forward chain + canonical JSON spec + first-row sentinel; verifier CLI exit codes + retention-purge tolerance; syslog-over-TLS via `BaseBatchedJob`; `X-PasswordPolicy-Signature` HMAC with replay window + idempotency UUID; dedicated `passwordpolicy_alert_cooldowns` table generalising F2's dedup; presigned filesystem-backed export download). User-confirmed scope: ships in 5.2.0 — G1–G12 in full (G9 ships whole, not infra-only); defers to 5.3 — Phase 12 § REST (ApiTokenService + ApiController) only; cut entirely — syslog UDP. Estimated 6-8 working days for the full set. Phase G is now unblocked.
- 10 alpha/beta branches merged into `5.x`, plus end-of-Phase-C work (P1.3 + P1.4 paired Email Notifications, P1.7 retention UI, P1.11 blocklist editor, P1.5 group-deletion listener) shipped on 5.x directly.
- Pro CP UI feature-complete: named-policy CRUD with presets + tri-state + divergence indicators + conflict UX, env-var inputs, blocklist subnav with custom dictionary editor + word-check tool, retention page with `notificationLogRetentionDays`, **Email Notifications subnav with token picker + per-(key, siteId) editing + sender overrides + AJAX test-send**, group-deletion observability listener, force-reset action.
- **Pro front-end Twig surface — closed 2026-05-01, polished 2026-05-02 via the C2 code-review bug-fix sweep.** `PasswordPolicyVariable` exposes status helpers (`daysUntilExpiry`, `isExpired`, `isExpiring`, `passwordStatus`, `lastPasswordChange`, `activeSessionCount`) and the full P1.12 builder surface: fluent render builders for fields (`passwordField`, `requirementList`, `strengthMeter`, `requirementsHint`, `passwordWidget`) + forms (`loginForm`, `passwordChangeForm`, `passwordResetForm`), data accessors (`requirements`, `requirementsText`, `requirementRules`), JS asset bundle (no Vite dep on consumer side), `bjeavons/zxcvbn-php` server-side strength engine (consolidated to a single engine in Phase F polish — drops the prior baseline rule-counter), a11y baseline, show/hide toggle. **Both `craft.passwordPolicy` (camelCase) and `craft.passwordpolicy` (legacy lowercase) handles work.** P2.4 absorbed.
- **Bug fix sweep — done 2026-05-02 (6 commits, all PHPStan clean).** C2 code-review followups + a 5.1.1 file-based config compatibility blocker. Twig tag layer (composite null-gating, `id()` setter alias on `PasswordResetFormTag`, `__toString()` docblock correction); controllers (explicit session invalidation via new `PasswordService::destroyOtherSessions()`, ValidationController context-input hardening); client asset (auto-register on any interactivity flag, blocklist-hit propagation in zxcvbn-php engine, cpTrigger-safe fallback URL with rebuilt CP strength bundle); HIBP 429 site-wide backoff cache; dual variable handle registration; SettingsModel alias for legacy `pwned` / `pwnedFailMode` keys. P1.12 fully closed (Layer 4b + bug fixes). Phase C2 closed-closed. See `progress.md` "Session: 2026-05-02" for per-bug details.
- Manual tests: **78/79 PASS** active C2 pass. **T1.2 + TX.2 + T9.7 covered by Pest** (no longer deferred — see `tests/Integration/Migrations/UpgradeTo520MigrationTest.php` and `tests/Integration/MultiSite/`). T12.6 (Enterprise audit), T13.6 + T13.11 (browser-driven AJAX UX + screen-reader a11y) gated by environment, not by code.
- **P1 backlog: 0 items remaining (Phase C2 closed-closed).**
- P1.8 (deployment docs) moved to Phase H — Enterprise must exist before authoritative deployment docs can be written.
- **P2 backlog: 1 item remaining** — P2.8 (Phase F, Phase G build plan draft). P2.1 + P2.2 closed as Phase D (2026-05-03). P2.4 absorbed into P1.12. **P2.5 closed as Phase E (2026-05-02).** P2.6 absorbed into Phase D verification gate (satisfied throughout).
- P3 (Enterprise — Phase 10/11/12) blocked on D + F. P4: future.
- **5.1.x maintenance line — 5.1.2 shipped 2026-05-02.** Three backports (TLS verify `e58f0d7`, fail-open log level `dbe050c`, sensitive-key strip `b85a6c9`) released as `5.1.2` (`833a038`). Tag pushed to origin. `origin/5.1.x` HEAD = `5.1.2` tag. Channel idle until a new security signal arrives — post-5.1.2 fixes on `5.x` (Phase D/E/F/F2/F3/G surfaces) all target code paths that don't exist in 5.1.x, so no backport candidates are currently outstanding.
- **Release strategy:** 5.2.0 ships as a single release covering Lite + Pro + Enterprise. Nothing tags / publishes until Enterprise (Phase 10–12) is complete and tested. Once the Phase G build plan is drafted (P2.8), revisit whether any G subset can defer to 5.3 if scope expands beyond a comfortable build cycle.
- **Phase G closed 2026-05-14.** G1–G12 shipped on `5.x`. Twelve features across 17K+ lines + Phase G post-review remediation Steps 1–8 (bundled fix-pack, dedicated `CRAFT_AUDIT_PII_KEY`, verify-then-decide pass on I4/I6/I7/N1–N6, NotificationLog/AuditLog/Policy element-ifications, G12 mailer-key regression resolution, G11 custom template paths, G3 compliance dashboard + reports). **Pest suite: 786 passing / 0 skipped / 1875 assertions.** Schema version `2.11.0`. ECS + PHPStan clean. Foundation-first principle held throughout — three record→element refactors landed before downstream features so user data never carries 5.2.0 → 5.3 migration debt. Phase G session log spans commits `cf3e2f1` → `be33546`. Release prep (Phase H) is now unblocked.
- Hard gate: Phase D + Phase F + Enterprise build (G) must pass before release prep (H). **All gates cleared.**

### Known regressions — resolved

- **Mailer-key SystemMessages registration missing for `password-policy:new-device-alert` + `password-policy:admin-security-alert`.** **Resolved by G12 (commit `ede5071`, 2026-05-13).** Both keys moved from `composeFromKey()` (mailer-templates path) to `_dispatch()` (editable-templates path) with per-site DB-stored seeds via `EmailDefaults::all()`. `_dispatchMailerKey()` deleted. `composeFromTemplate()` widened to `?User` for admin-alert mode. Resend deferred (these types are non-resendable until 5.3+ adds a `templateVarsJson` column — additive future work, foundation-positive).

### Phase G post-review remediation (2026-05-07 → 2026-05-14) — done

All eight steps shipped. Final commit `be33546` (G3). Cumulative session range `4ca1c0a` (Step 1 fix-pack) → `be33546` (G3 finale). Detailed step-by-step status:

| Step | Title | Commit | Date |
|---|---|---|---|
| 1 | Bundled fix-pack (C1, C2, C3, I1, I2) | `4ca1c0a` | 2026-05-08 |
| 2 | I5 dedicated `CRAFT_AUDIT_PII_KEY` + CLI generator | `dc5bbd1` | 2026-05-09 |
| 3 | Verify-then-decide on I4, I7, N1–N6 | `87149dd` | 2026-05-10 |
| 4 | `NotificationLogRecord` → `NotificationLogElement` | `2d0144e` | 2026-05-10 |
| 5 | `AuditLogRecord` → `AuditLogElement` | `ba520a5` | 2026-05-11 |
| —  | FK dedup follow-up | `f800d72` | 2026-05-11 |
| 6 | `PolicyRecord` → `PolicyElement` | `2809614` | 2026-05-12 |
| 7 | G12 — mailer-key regression resolution | `ede5071` | 2026-05-13 |
| 8a | G11 — Enterprise custom email template paths | `fd2c806` | 2026-05-14 |
| 8b | G3 — Compliance dashboard + reports | `be33546` | 2026-05-14 |

Original review summary preserved below for the historical record.

---



Code review across the 9 Phase G commits (cf3e2f1 → 3dccebafa, 17K+ lines) surfaced 9 verified issues + 1 false positive (the reviewer claimed `AuditExportCompleteEvent` was missing from `events.md`; it's at line 402). Each finding manually verified against the cited file:line before logging here.

**Step 1 — bundled fix-pack (next commit, ~80 lines, zero new functionality)**

| ID | File:line | Fix |
|---|---|---|
| C1 | `SiemForwardJob.php:282-288` | Replace `throw new RuntimeException` inside `_recordRowOutcome()` catch with `Craft::error()` + `return`. Method's docblock declares "best-effort, never rethrown" — current code violates the contract and causes duplicate SIEM forwarding on retry. |
| C2 | `AuditController.php:870` and `:262` | Replace `$query->all()` with `->batch(1000)` cursor. Production-scale audit logs OOM under `->all()`. |
| C3 | `AuditExportController.php:306-327` | Drop the closure-as-stream pattern; use `return $this->asRaw($payload)` with `Content-Type` + `Content-Disposition` headers. Memory budget at the 1000-row sync threshold is fine. Closure currently returns `[true, true]` instead of `[string $data, bool $finished]`, so Yii echoes a stray `"1"` after the payload. |
| I1 | `AuditLogService.php:161,172`; `AuditController.php:67,76`; `m260507_081852_RecomputeAuditLogChain.php:61,79` | Promote `GENESIS_PREVIOUS_HASH` + `CANONICAL_DATE_FORMAT` from triplicated `private const` to single `public const` on `AuditLogService`. Other two sites reference via class name. Drift between the three sites would silently invalidate every chain hash without test or static-analysis signal. |
| I2 | `PolicyService.php:270` | `Carbon::now('UTC')->format('Y-m-d H:i:s')` instead of `new \DateTime()`. Server-local TZ on non-UTC servers stamps wrong; every other datetime write in the codebase uses Carbon UTC. |

Verify gate: ECS + PHPStan + Pest (suite at 713 / 1618). No suite delta expected (fixes don't add tests; existing tests should continue to pass).

**Step 2 — I5 architectural decision (after step 1, user choice required)**

`AuditLogService::_hashUserIdentifier()` (line 603) uses `Craft::$app->getConfig()->getGeneral()->securityKey` as the HMAC secret. The privacy USP framing — "rotating the audit-PII key destroys historical correlation without breaking site security" — is not currently true; rotating `securityKey` also breaks session signing, security tokens, etc.

Options:
- **(a)** Add dedicated `auditPiiKey` (or `auditPiiSalt`) to `SettingsModel` + `config/password-policy.php`. Document key rotation as a privacy lever. Independent of `securityKey`. **Recommended.**
- **(b)** Update USP / marketing text to reflect current behavior. No code change.
- **(c)** Drop the keyed hash entirely; use a non-cryptographic correlation scheme (or no correlation).

Decision pending. Step 2 commit shape depends on choice.

**Step 3 — verify-then-decide on remaining findings**

Items not yet verified in the code (reviewer claims, accuracy unverified):

- **I4** — SIEM + Webhook `sendTestEvent()` race: `logEvent()` then `ORDER BY id DESC LIMIT 1` could pick a stale row if `logEvent()` fails silently. Fix: have `logEvent()` return the new row id.
- **I6** — SIEM uses non-transparent newline framing instead of RFC 6587 octet-count framing. Interop concern only; not a current-correctness bug since plugin-produced syslog messages don't contain embedded LF.
- **I7** — `SiemForwarderController::actionSendTest()` exposes raw `$e->getMessage()` to CP admin. Defense-in-depth concern.
- **N1-N6** — six nice-to-have items (docblock-code mismatch on a non-existent cache, IPv4 hash without HMAC, RotateWebhookSecretJob warning on null, BlocklistService TOCTOU, permission flat-vs-nested convention, AuditExportController filename regenerated at serve time).

For each: verify against current code → fix inline if real and small → file in `ideas.md` if real but post-5.2.0 → drop if false.

**Step 4 — `NotificationLogRecord` → `NotificationLogElement`**

Foundation refactor. Per the user-stated principle (`feedback_foundation_first_no_refactor_deferrals.md`), record-to-element conversions ship in 5.2.0 because the post-release migration cost is severe. Schema rewrites `passwordpolicy_notification_log.id` to FK `craft_elements.id` (CASCADE delete). New `NotificationLogElement` + `NotificationLogQuery` + element actions (Resend, Delete, Restore). `NotificationActivityController` index swaps to native element-index rendering; per-user panel switches to `NotificationLogElement::find()`. `NotificationService::_logNotification` and `resend()` adapt to the element surface. Playground test data is truncated by the migration (unreleased; documented in migration body). Schema bump 2.8.0 → 2.9.0.

**Step 5 — `AuditLogRecord` → `AuditLogElement`**

Same refactor pattern as Step 4 but on the bigger audit-chain surface. Element actions: View detail, Export selection, Delete (admin override only). Element-delete cooperates with retention purge (`EVENT_AUDIT_CHAIN_ROTATED` still fires; element soft-delete via `dateDeleted` is the new boundary). Chain hash computed from element-record content unchanged — `canonicalize()` continues to produce bit-identical bytes. `password-policy/audit/verify` console command continues to walk via the existing query (element layer is purely additive). Schema bump 2.9.0 → 2.10.0.

**Step 6 — Policy element-ification decision checkpoint**

User-requested checkpoint after Steps 4 + 5 land. Revisit whether `PolicyRecord` should also become `PolicyElement` for the same reason. Project-config-sync interaction is the wrinkle to think through. If approved: Step 6 implementation lands as a parallel refactor. If declined: PolicyRecord stays as-is for 5.2.0, captured in ideas.md as a 5.3+ consideration only if it can be done additively without migration (likely impossible — same reason we're elementifying now).

**Step 7 — G12 (mailer-key regression resolution)**

Move `new-device-alert` + `admin-security-alert` keys to the editable-templates path per the existing comments. Builds on the element-backed notification surface from Step 4.

**Step 8 — G11 + G3** in some order. Phase G ends. Release prep (Phase H) starts.

Skill-gap learnings from Phase G review (4 items: shared constants public-not-private; queue-job best-effort rethrow contract; HMAC vs bare hash for PII; Yii Response::$stream callable signature) are tracked outside this plan in the user's skill files.

---

## 2. Manual testing remaining

Per-test results in `manual-tests.md`. Phases A + B closed; nothing remains in this section that's not gated on Enterprise.

### Pro CRUD + resolver — done 2026-04-29 (all PASS)

- T5.12 — delete policy + CASCADE cleanup verified
- T5.14 — edition gating: Lite returns 403, no subnav; Pro restores both
- T5.15 — subnav toggle works on `enablePerGroupPolicies` change
- T5.16 — conflict notice + banner cycle through all four states

### Pre-release security — done 2026-04-30 (4 PASS, 2 deferred)

- T7.3 — PASS via code review (`SettingsController::actionSave` unconditional unset blocks for Pro/Enterprise keys)
- T1.3 — PASS via code review (`_seedPasswordHistory` toggles `enableLogging`/`enableProfiling` off, restores in finally)
- T1.4 — PASS empirically (`ddev craft plugin/uninstall password-policy` drops all 6 tables in reverse FK order; reinstall restores cleanly)
- TX.3 — PASS via analysis + earlier T0.4 empirical grep (no sensitive keys reach logs)
- T1.2 + TX.2 — covered by Pest 2026-05-02 (Phase E6 commit `c164646` — `tests/Integration/Migrations/UpgradeTo520MigrationTest.php`)

### Enterprise — pending QA pass

T4.1–T4.6 (audit logging) unblocked 2026-05-14 — Phase G shipped. T14.x–T19.x rows for the new Phase G surfaces (hash chain, verifier CLI, compliance dashboard, SIEM forwarder, webhook forwarder, audit export, custom template paths, Enterprise notification keys) need authoring in `manual-tests.md` as part of Phase H QA prep — ~25-30 new T-row entries per the build plan's "Final deliverables" section.

---

## 3. Backlog

### P1: must-have for stable 5.2.0

| ID | Title | Notes |
|---|---|---|
| ~~P1.2~~ | ~~Common passwords expansion~~ — done 2026-04-30 | `src/data/common-passwords.php` now ships 10,000 entries from SecLists `Passwords/Common-Credentials/10k-most-common.txt`, lowercased + deduped. CLI seed verified: 10000 rows in `passwordpolicy_blocklist` with `source='common'`. |
| ~~P1.3~~ | ~~Email notifications (Pro) — Path B plugin-managed editor~~ — done 2026-04-30 | New table `passwordpolicy_notification_templates` (one row per (key, siteId) with JSON content column — Craft 5 element-content idiom). EmailDefaults seeds `expiry-reminder` for every enabled site at install + via the `Sites::EVENT_AFTER_SAVE_SITE` propagation listener. NotificationTemplateService + NotificationTemplateController + `_notifications/_index.twig` + `_notifications/_edit.twig`. asCpScreen with General/Advanced/Test tabs; token-picker chips with click-to-copy; sender-overrides with `suggestEnvVars`; AJAX test-send rendered against current admin with `daysUntilExpiry: 7`. Pro-gated end-to-end: subnav, controller, service method, queue job, console command. |
| ~~P1.4~~ | ~~NotificationController console command~~ — done 2026-04-30 | `password-policy/notification/send-expiry-reminders [--user=<id>]` enqueues `SendPasswordExpiryRemindersJob` (BaseBatchedJob, batchSize=100, ttr=300, canRetry≤5). `ExpiringPasswordUserBatcher` recomputes recipient set per slice for natural retry idempotency; per-user soft-fail in `processItem`. No `actionPrune` — `gc/run` already covers it. Lite returns `ExitCode::UNSPECIFIED_ERROR` with stderr "Pro edition required." |
| ~~P1.5~~ | ~~Group deletion cleanup listener~~ — done 2026-04-30 | `UserGroups::EVENT_BEFORE_APPLY_GROUP_DELETE` (not `AFTER` — fires after FK cascade so junction rows would be gone). Listener queries affected policies before cascade and logs them via `$plugin->log()`. Defensive try/catch — never blocks group deletion. Observability seam for future Enterprise audit logging. |
| ~~P1.7~~ | ~~`notificationLogRetentionDays` UI field~~ — done 2026-04-30 | `forms.textField` added to `src/templates/_settings/retention.twig` inside the Pro block (after `expiryReminderDays`, with `<hr>` separator). Field has its own `info` span explaining what notification log entries are (dedup window for expiry reminders). Added to `SettingsController::actionSave` Pro-strip list. Operational "(see documentation)" pointer to the GC cron deferred until P1.8 docs exist. |
| P1.8 | ~~Deployment documentation~~ — moved to Phase H | Migration guide 5.1.1 → 5.2.0, GC cron setup, blocklist deployment notes, edition comparison table. **Moved to Phase H (release prep)** because authoritative deployment docs need Enterprise to exist before they can describe the full edition comparison + Enterprise audit cron. CHANGELOG already drafted. Operational pointers ("(see documentation)" parentheticals on `notificationLogRetentionDays` + `auditLogRetentionDays` instructions) get appended once docs land. Frame the `password-policy/gc/run` cron as the **recommended production setup** for retention-managed tables — don't say "pruning is automatic." |
| ~~P1.11~~ | ~~Custom dictionary editor (Pro)~~ — done 2026-04-30 | New top-level **Blocklist** subnav (between Policies and Settings), Pro-gated. Page consolidates: stats prose with SecLists 10k source citation, Last Seeded callout (`<blockquote class="note tip">`, never-seeded variant escalates to `note warning`), "Update Common Passwords" cron-driven seed button, "Check a word" tool (AJAX, results render in `<blockquote class="note tip|warning">` matching), and `forms.editableTableField` for custom words with diff-on-save (numeric rowId = keep, non-numeric = insert, missing existing IDs = delete). Permission split: `pp:blocklist-view` gates page access, `pp:blocklist-manage` (nested) gates writes. Schema includes nullable `policyId` column from day one (Phase G uses it for per-policy custom dictionaries — Enterprise tier). Validator emits source-aware messages: bundled common → "too common, choose a more unique password"; custom → "blocked, choose a different one". Old `BlocklistUtility` deleted. |
| ~~P1.12~~ | ~~Pro front-end Twig surface~~ — fully closed 2026-05-01 (incl. Layer 4b strength engine unification); strength engine consolidated 2026-05-03 in Phase F polish | Image-optimize-style fluent render builders shipped under `craft.passwordpolicy.*` (`passwordField`, `requirementList`, `strengthMeter`, `requirementsHint`, `passwordWidget`, `loginForm`, `passwordChangeForm`, `passwordResetForm`). Data accessors `requirements()` / `requirementsText()` / `requirementRules()` with optional `groups` for anonymous group preview. Vanilla-JS client asset (`PasswordPolicyClientAsset`) auto-registered by any builder with `liveValidation: true` — no Vite assumption on consumer side. Single zxcvbn-php strength engine drives the CP meter and the front-end render builders (the prior dual-engine baseline-vs-zxcvbn architecture and `useZxcvbnStrength` toggle were dropped in Phase F polish — `bjeavons/zxcvbn-php` is in `require`, not optional, so the baseline rule-counter saved nothing while adding complexity). Pro upsell on strength is the front-end render-builder surface, not a different algorithm. New `Front\PasswordChangeController` for logged-in change. **Layer 4b (CP-side indicator)** refactored to consume the same AJAX `/validate` endpoint the front-end builders use — single engine, blocklist-aware, per-group-aware. Bundle dropped from ~1.65 MB to ~2.2 KB after `@zxcvbn-ts/*` deps were removed. The original "replace Craft's native zxcvbn meter" framing in `history/phase-c2-build-plan.md` was a spec-premise error — Craft 5 ships no client-side zxcvbn meter; the work was actually unifying the plugin's own duplicate implementation. T13.1–T13.12 in `manual-tests.md`. Full reference at `../user/features/frontend-twig.md`. |
| ~~P1.13~~ | ~~HIBP-on-login (Pro)~~ — done 2026-05-01 | Listener on `User::EVENT_BEFORE_AUTHENTICATE` (only Craft 5 hook with synchronous plaintext-in-scope access — research write-up in `progress.md`). Hashes plaintext to SHA-1, sends only 5-char k-anonymity prefix to HIBP, never logs plaintext / full hash / bucket suffix. On match: sets `passwordResetRequired = true` (saved with `muteEvents` to avoid recursion), sends `breach-detected` notification email (new key in `EmailDefaults`), writes audit-log entry on Enterprise + audit-toggle, fires `EVENT_BREACH_DETECTED`. 24h dedup cache keyed by `(userId, sha1Prefix)` with string values to avoid Yii's bool-false / missing-key collision. Login never blocked. New setting `enableHibpOnLogin: bool` (default true, Pro). T12.1–T12.5 in `manual-tests.md`. |
| ~~P1.14~~ | ~~Registration helper service (Lite + Pro per-group validation)~~ — done 2026-05-01 | New `RegistrationService::register(array $params): User`. Resolves group handles up front (more dev-friendly than IDs), populates `setGroups()` BEFORE `validate()` so `UserRules::defineRules()` picks up the per-group context via `PolicyResolverService::resolveForUser()`. On success: persists, assigns groups, optionally sends activation email, fires `UserRegisteredEvent`. Throws `\InvalidArgumentException` on missing required params, unknown handles, or validation failure (with attribute-prefixed messages flattened). T11.1–T11.5 in `manual-tests.md`. |
| ~~P1.15~~ | ~~Event catalog + documentation~~ — done 2026-05-01 | `../user/reference/events.md` published with FQ class names, payload tables, edition tiers, and example listener code for `PasswordChangedEvent` (Lite), `UserRegisteredEvent` (Lite), `BreachDetectedEvent` (Pro), `PasswordValidationEvent` (Lite). README cross-link via new "Events" section. Future events placeholder for 5.3+/Phase G. Cross-cutting build rule: every new feature ships with its event class defined + a `user/reference/events.md` row in the same commit. |

### P1: shipped (this session)

- P1.1 — manual testing tracking (moved to `manual-tests.md`)
- P1.6 — group policies CP UI (named-policies CRUD, see `../user/features/per-group-policies.md`)
- P1.9 — save-time conflict notice (`PolicyController::actionSave()` → `setNotice()` when `policy.minLength > globalSettings.maxLength`)
- P1.10 — edit-screen conflict banner (`PolicyController::actionEdit()` → `noticeHtml()` warning blockquote, combined with read-only notice when both apply)

### P2: should-have for 5.2.0

| ID | Title | Notes |
|---|---|---|
| ~~P2.1~~ | ~~User index table attributes~~ — closed as Phase D 2026-05-03 | Six Lite-tier columns (`lastPasswordChange`, `daysUntilExpiry`, `expired`, `resetRequired`, `status`, `lastChangeReason`) on every Craft edition + three Pro-tier columns (`breachedRecently` everywhere; `policyDrift` + `appliedPolicies` on Craft Team-or-better). Composite seven-state status priority (breached / expired / reset-required / policy-drift / expiring-soon / never-changed / ok). All columns + condition rules backed by `UserIndexService`'s bounded-query preload. See `history/progress-phase-d.md` § D2 for the full surface. |
| ~~P2.2~~ | ~~Admin password change action~~ — closed as Phase D 2026-05-03 | Two element actions: `ChangeUserPassword` (single-user; opens JS modal; explicit `AuditContext::adminChange` propagated via `UserStateService`'s explicit-context slot to the central history listener) and `SendPasswordResetEmail` (bulk; pins `pendingResetReason = AdminForceReset` BEFORE mailer call). New permission `pp:change-user-passwords` gates both. New `UserPasswordController` (CP POST, elevated session required, rejects bulk-shaped POSTs / self-targets / mismatched confirms / policy-validation failures). Migration `m260502_214932_AddAuditShapeToPasswordHistory` adds `changeReason`, `changedByUserId`, `changedFromIp`, `changedFromUserAgent` columns + `passwordpolicy_user_state` table. Storage: Option A — capture on every edition, gate exposure not capture (`project_audit_capture_principle.md`). See `history/progress-phase-d.md` § D0 + D3 for the full surface. |
| ~~P2.4~~ | ~~`passwordField()` Twig function~~ — absorbed into P1.12 | Original entry was scoped narrowly to a single front-end input with strength indicator. P1.12 expands the surface to a full image-optimize-style render builder API covering field renderers + form renderers + JS asset bundle + strength engine A+B. The original deliverable becomes one method (`craft.passwordPolicy.passwordField()`) inside the larger surface. |
| ~~P2.5~~ | ~~Integration test suite~~ — closed as Phase E 2026-05-02 | 18 commits across E1–E6 plus `fix(hibp)` + `docs(ideas)`. Pest suite at 329 passing / 0 skipped / 634 assertions. Coverage: validators (Sequential, Repeated, Contextual, MinimumCharacterTypes, CommonPassword, PasswordHistory), services (Blocklist, PasswordHistory, PolicyResolver, Strength, Hibp [via Guzzle MockHandler + HibpClientFake]), models (GroupPolicyModel boolean tri-state, SettingsModel legacy alias), controllers (ValidationController context hardening, destroyOtherSessions web + console), Twig tags (PasswordWidgetTag composite null-gating + Markup return contract), migrations (5.1.1 → 5.2.0 upgrade replay covering T1.2 + TX.2), multi-site (notification template propagation + FK CASCADE soft-delete contract covering T9.7). Test infrastructure: `tests/bootstrap.php` (`$_SERVER` pin block — memory gap #16), `TestCase`, `MigrationTestCase` + `MultiSiteTestCase` non-transactional bases (DDL + project-config writes auto-commit; transaction wrapper inadequate), factories (`UserFactory`, `GroupFactory`, `PolicyFactory`, `BlocklistFactory`, `PasswordHistoryFactory`, `SessionFactory`), stubs (`HibpClientFake`, `WebRequestStub`, `UserStub`, `TestGuzzleConfig`). HibpClient interface extracted in E1 (`refactor(hibp)` commit `08c0702`) so the production code is testable; same pattern positions Phase 12's SIEM + webhook services. Six skill gaps captured (#15–19 + Codeception transitive load, PHPUnit `$_SERVER` collision, Solo edition cap, Pest `uses()` ordering, Sites soft-delete) — see `feedback_skill_gaps.md`. |
| ~~P2.6~~ | ~~`allowAdminChanges` read-only verification~~ — absorbed into Phase D verification gate; satisfied 2026-05-03 | Every new Phase D CP affordance respects `allowAdminChanges = false`. `ChangeUserPassword` + `SendPasswordResetEmail` actions return null `getTriggerHtml()` in read-only mode (triggers don't register on the index); `UserPasswordController::beforeAction()` enforces the constraint as a defense-in-depth 403 even on bypass. The user-edit "tab" page (D4) still renders in read-only mode (data is fine to view) but renders `readOnlyNotice()` + `disabled` on the force-reset button. Verified by Pest tests in `UserPasswordControllerTest`, `ChangeUserPasswordActionTest`, `SendPasswordResetEmailActionTest`, and `PasswordSecurityTabTest`. |
| ~~P2.8~~ | ~~Draft Phase G build plan~~ — drafted 2026-05-06 → [`internal/phase-g-build-plan.md`](./phase-g-build-plan.md); scope confirmed 2026-05-06 | Layered build plan covering G1 hash-chained audit + G2 verifier CLI + G3 compliance dashboard + G4 policy-change diffs + G5 PII allowlist + G6 per-policy blocklist + G7 AlertCooldownService + G8 syslog-over-TLS forwarder + G9 webhook (full surface) + G10 streaming export + G11 custom template paths + G12 Enterprise notification keys. Locked architecture: SHA-256 forward chain, canonical JSON with alphabetical key order + UTC ISO 8601 + first-row sentinel `'0'×64`, `BaseBatchedJob`-driven SIEM forwarders, `X-PasswordPolicy-Signature: sha256=<hex>` HMAC scheme + 5-min replay window + idempotency UUID header, dedicated `passwordpolicy_alert_cooldowns` table generalising F2's dedup pattern, presigned filesystem-backed export download. **User-confirmed scope (2026-05-06):** ships in 5.2.0 — G1 through G12 in full (G9 ships whole, not infra-only); defers to 5.3 — Phase 12 § REST surface (ApiTokenService + ApiController) only; cut from the matrix entirely — syslog UDP forwarder protocol. Estimated 6-8 working days. |
| ~~P2.9~~ | ~~Notifications activity surface (Phase F2)~~ — closed 2026-05-06 | Single commit `feat(notifications): activity surface — capture-on-failure + resend + per-user panel`. Schema migration adds `status` / `recipientEmail` / `siteId` / `subject` / `body` / `errorMessage` / `resentFromId`; idempotent migration `m260506_174529_AddNotificationLogActivityColumns`; `Install.php` matched; `schemaVersion` 2.4.0. `NotificationService::_dispatch()` writes rows on both success + failure; `composeFromTemplate()`'s new `&$rendered` out-param captures rendered subject + body without a redundant second renderString pass. `_hasRecentNotification()` filters on `status = NotificationStatus::Sent->value` so failed-then-retried doesn't suppress. `resend(NotificationLogRecord)` re-renders fresh from current template, bypasses dedup, chains via `resentFromId`, rejects mailer-key types. `NotificationActivityService` (read-side), `NotificationActivityController`, URL rules, `Notifications → Activity` sibling subnav. Per-user panel embedded on Password Security screen. `NotificationStatus` backed enum (Sent / Failed). Notification-log GC pruner ungated from Pro (capture runs on every edition per `project_audit_capture_principle.md`). Three Pest test files: NotificationServiceCaptureTest + NotificationServiceResendTest + NotificationActivityServiceTest. Bounce ingestion deferred to `ideas.md`. |

### P3: Enterprise (gated)

| ID | Title | Notes |
|---|---|---|
| Phase 10 | Device tracking + login anomaly | DeviceTrackingService, KnownDeviceRecord, ua-parser/uap-php dependency (needs approval), login event listener, alerts, DeviceController CLI. |
| Phase 11 | Compliance dashboard + audit-trail integrity | ComplianceDashboardUtility (aggregates), ReportController (HTML/PDF/CSV export), compliance mapping, PCI-DSS tension. **Includes:** CP-wide policy conflict alert via `Cp::EVENT_REGISTER_ALERTS` — surfaces conflicts on every CP page (Pro/Lite get P1.9 + P1.10 only, Enterprise adds this). **Compliance-grade audit-trail enhancements** (added 2026-05-01 from Trails competitive analysis — see `../user/features/audit-logging.md` "Compliance-grade enhancements" section for design detail): (a) **Hash-chained audit rows** — append-only `previousHash` column, `sha256(canonicalRowJson + previousHash)`, no Merkle batching needed at password-event volume. Turns "we have a log table" into "we have a tamper-evident audit trail." (b) **Independent verifier CLI** — `password-policy/audit/verify` walks the chain, reports the first break, exits non-zero. Open-source, auditor-runnable — credibility multiplier on (a). (c) **Field-level before/after diffs on policy changes** — when an admin edits a named policy, the audit row captures the structured diff (e.g. `{minLength: {old: 8, new: 12}}`), maps to ISO 27002 A.5.37 + SOC 2 CC8.1 change-management evidence. (d) **Explicit PII allowlist registered per event type** — codify the existing implicit allowlist as inspectable per-event-class config that fails closed; makes the privacy-by-design story documentable for auditors. |
| Phase 12 | SIEM + webhooks + API tokens + audit-export streaming + alert cooldown | SiemService, WebhookService, ApiTokenService, ApiController, SiemForwardJob, circuit breaker, HMAC-SHA256 webhook signatures. **Added 2026-05-01:** (e) **`AlertCooldownService`** — generalised cooldown/dedup logic for alert emails (HIBP-on-login mass detections, group-deletion cascades, force-reset bursts). Reuses the `notificationLogRetentionDays` dedup pattern from P1.3 but per-event-class. Each new alert type registers its cooldown window rather than reinventing throttling. (f) **Streaming audit-log exports** — extend `AuditController::actionExport` to stream CSV/JSON via `BaseBatchedJob` with no PHP memory ceiling, queue-driven for large date ranges. Same pattern as P1.4's `SendPasswordExpiryRemindersJob`. |
| (Phase G addition) | Per-policy custom blocklist | Enterprise-tier extension of P1.11. Schema: nullable `policyId` column already added in 5.2.0 install migration. Adds: per-policy editor tab on the policy edit screen (admins scope custom words to specific named policies — block customer names for sales reps, project codenames for engineering, etc.). `BlocklistService::addCustomWord()` extends to `addCustomWord(string, ?int $policyId = null)`. `CommonPasswordValidator` merges global (`policyId IS NULL`) + applicable per-policy entries based on the user's resolved policy set. Edition strip on save prevents Pro from accidentally writing per-policy entries. Cache key includes policyId set. Specops-style differentiator. |
| (Phase G addition) | Custom email template paths | Enterprise-tier extension of P1.3. Adds a "use Twig template" override mode on each notification template — admin specifies a path (e.g. `_emails/expiry-reminder.twig`), plugin renders that instead of the DB-stored body. Whitelabeling / brand-enforcement use case for Enterprise customers who want version-controlled, dev-managed templates with full HTML support. Schema: nullable `templatePath` field added to the JSON content shape on `passwordpolicy_notification_templates`. Edition strip on save prevents Pro from writing template paths. **Rejected for 5.2.0 Pro per session 2026-04-30** — Pro stays DB-textarea-only because template-path mode reopens HTML body and contradicts the "edit on production" promise. Multi-site framing (the original motivation) is already handled in 5.2.0 by per-site rows + Twig-rendered body — `{% include %}` of site templates from within the body textarea provides the same flexibility for Pro customers without a UI mode switch. |

### P4: future

- Plugin documentation site (craftpulse.com/docs/password-policy)
- v5.3.0: per-group alerts, IP geo, inactive accounts, min change interval
- CP password field show/hide toggle (JS injection) — partially redundant with P1.12's CP indicator; could collapse to "extend `cp-strength.js` to inject toggle on the same selector"
- Policy summary view (plain-language effective policy per user)
- CLI debug: `policy/resolve --user=<id>`, `policy/validate --user=<id> --password=<test>`
- **Remove `pwned` / `pwnedFailMode` `SettingsModel` aliases in 5.4** — two-minor-version grace from 5.2.0 (deprecation logs on every `getSettings()` call for sites still using the legacy file-config keys; once consumers have had two minors to migrate, drop the alias four-hook layer). Don't pin to 5.3 — give consumers the grace.

---

## 4. Build order

| Phase | Items | State |
|---|---|---|
| A | Audit fix-ups — A1 force-reset action added, A2 muteEvents applied, A3 was a non-issue, A4 UID validation added | done 2026-04-29 |
| B | Pre-release security tests — T7.3 PASS, T1.3 PASS, T1.4 PASS, TX.3 PASS, T1.2 + TX.2 deferred to P2.5 | done 2026-04-30 |
| C | Original P1 backlog — P1.2 / P1.3 / P1.4 / P1.5 / P1.7 / P1.11 done 2026-04-30. P1.8 (deployment docs) deferred to Phase H since Enterprise must exist first. | done 2026-04-30 |
| C2 | P1 expansion — Pro front-end surface bundle (P1.14 RegistrationService → P1.13 HIBP-on-login → P1.12 front-end Twig render builders + JS asset + strength engine A+B → P1.15 events catalog). | fully closed 2026-05-01 (Layer 4b strength engine unification landed in a focused session — single AJAX engine for both CP and front-end surfaces, ~1.65 MB bundle reduction) |
| E | Testing infrastructure (P2.5, scope-expanded) — Pest covers C2 surface + bug fix sweep + deferred manual tests | done 2026-05-02 (18 commits, 329 passing / 0 skipped / 634 assertions) |
| D | User index integration (P2.1, P2.2; absorbs P2.6 `allowAdminChanges` verification gate). D0 audit context surface; D1 audit listener wiring; D2 user-index columns + condition rules; D3 admin element actions + UserPasswordController; D4 user-edit "tab" via sidebar pointer + UserSecurityController. | done 2026-05-03 (19 commits, 513 passing / 0 skipped / 1049 assertions) |
| F | Polish + UI sweep (2026-05-03 / 2026-05-06) — `Cp::statusLabelHtml()` rewrite, expiry-gated columns, `EVENT_DEFINE_EDIT_SCREENS` (replaced sidebar pointer workaround), `EVENT_DEFINE_ACTION_MENU_ITEMS` listener, modal styling + elevation, `passwordResetRequired` hydration fix. **P2.4 absorbed into P1.12; P2.6 absorbed into D.** | done 2026-05-06 (1 commit) |
| F2 | Notifications activity surface (P2.9) — `notification_log` schema rewrite, capture-on-failure, resend pipeline, CP activity index, per-user panel | done 2026-05-06 (1 commit, +3 Pest test files; suite at 551 / 1151) |
| F3 | P2.8 — draft Phase G build plan → [`internal/phase-g-build-plan.md`](./phase-g-build-plan.md) | done 2026-05-06 (1238-line layered plan covering G1–G12; deferral recommendation pending user confirmation) |
| G | Enterprise (Phase 10, 11, 12) — driven by P2.8 build plan. G1–G12 + post-review remediation Steps 1–8 all shipped. | done 2026-05-14 (suite at 786 / 1875; commits `cf3e2f1` → `be33546`) |
| H | Release prep + deployment docs (P1.8) — tag 5.2.0, Plugin Store listing, marketing copy, migration guide review, deployment/cron docs, Enterprise QA pass (T12.6 + T14.x–T19.x), authoritative editions comparison table | **unblocked 2026-05-14** — ready to start |
| **(parallel)** | **5.1.x maintenance line — 5.1.2 shipped 2026-05-02.** Three backports (TLS verify, fail-open log level, sensitive-key strip) released as `5.1.2` (`833a038`) and pushed to origin. Channel idle until a new security signal warrants a 5.1.3 — post-5.1.2 5.x fixes all target 5.2.0-only surfaces, so no current backport candidates. Independent of the linear A → H sequence. | done 2026-05-02 |

Gates:
- B cannot start until A is complete (don't run security tests against known-broken code).
- C2 cannot start until C is complete (P1.13 builds on the email-notifications infrastructure shipped in P1.3+P1.4; P1.14 fires events that P1.15 catalogues).
- E cannot start until C2 is complete (Pest covers the C2 surface; that surface had to land first). **Closed 2026-05-02.**
- D cannot start until E is complete (Phase D extends the codebase with new CP surfaces; Pest must cover the existing C2 surface before new code lands on top). **Closed 2026-05-03.**
- F cannot start until D is complete (P2.8 Phase G build plan benefits from the user-index work being in-hand for cross-references). **F + F2 + F3 all closed 2026-05-06.**
- G cannot start until F is complete (Phase G needs the P2.8 build plan to lock architectural decisions before code). **Closed 2026-05-14.**
- H cannot start until G is complete (single 5.2.0 release covers all editions; nothing tags until Enterprise is built and tested). **Unblocked 2026-05-14.**

---

## Reference (sections 5–7) → moved

Sections 5 (completed work), 6 (settled architecture decisions) and 7 (source-code inventory) live in [`reference.md`](./reference.md). They don't change session-to-session — keeping them out of `plan.md` keeps the active plan focused on what still needs to land.

- §5.1–5.5 — phases shipped + bug fixes + features built per session → [`reference.md` §5](./reference.md#5-reference-completed-work)
- §6.1–6.7 — settled architecture decisions (compliance view, tri-state semantics, edition switching, etc.) → [`reference.md` §6](./reference.md#6-reference-architecture-decisions)
- §7.1–7.4 — current source-code inventory + integration-test edge cases → [`reference.md` §7](./reference.md#7-reference-source-code-inventory)
