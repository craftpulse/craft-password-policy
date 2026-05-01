---
title: Password Policy v5.2.0 — Master Plan
version: 5.2.0
branch: 5.x
last_updated: 2026-05-02
status:
  pro_ui: feature_complete
  manual_tests: 78/79 PASS (T1.2 + TX.2 + T9.7 deferred; T12.6 + T13.6 + T13.11 + T13.12 require browser/SR/Enterprise gates)
  p1_remaining: 0
  p2_remaining: 4 (P2.4 absorbed into P1.12)
  enterprise: not_started
release_strategy: single_5_2_0_includes_all_editions
gate: enterprise_must_complete_before_release_prep
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
| 2 | [Manual testing remaining](#2-manual-testing-remaining) | done — 56/57 PASS, 3 deferred to P2.5 (T1.2 + TX.2 + T9.7) |
| 3 | [Backlog](#3-backlog) | active |
| 4 | [Build order](#4-build-order) | active |
| — | [Reference (completed work, architecture, inventory)](./reference.md) | done, skippable |

State legend: `active` = read now, `pending` = scheduled, `done` = built, `blocked` = gated, `settled` = decided.

---

## 1. Status

- 10 alpha/beta branches merged into `5.x`, plus end-of-Phase-C work (P1.3 + P1.4 paired Email Notifications, P1.7 retention UI, P1.11 blocklist editor, P1.5 group-deletion listener) shipped on 5.x directly.
- Pro CP UI feature-complete: named-policy CRUD with presets + tri-state + divergence indicators + conflict UX, env-var inputs, blocklist subnav with custom dictionary editor + word-check tool, retention page with `notificationLogRetentionDays`, **Email Notifications subnav with token picker + per-(key, siteId) editing + sender overrides + AJAX test-send**, group-deletion observability listener, force-reset action.
- **Pro front-end Twig surface — closed 2026-05-01, polished 2026-05-02 via the C2 code-review bug-fix sweep.** `PasswordPolicyVariable` exposes status helpers (`daysUntilExpiry`, `isExpired`, `isExpiring`, `passwordStatus`, `lastPasswordChange`, `activeSessionCount`) and the full P1.12 builder surface: fluent render builders for fields (`passwordField`, `requirementList`, `strengthMeter`, `requirementsHint`, `passwordWidget`) + forms (`loginForm`, `passwordChangeForm`, `passwordResetForm`), data accessors (`requirements`, `requirementsText`, `requirementRules`), JS asset bundle (no Vite dep on consumer side), strength engine A baseline + B Pro opt-in (`bjeavons/zxcvbn-php`, approved 2026-05-01), a11y baseline, show/hide toggle. **Both `craft.passwordPolicy` (camelCase) and `craft.passwordpolicy` (legacy lowercase) handles work.** P2.4 absorbed.
- **Bug fix sweep — done 2026-05-02 (6 commits, all PHPStan clean).** C2 code-review followups + a 5.1.1 file-based config compatibility blocker. Twig tag layer (composite null-gating, `id()` setter alias on `PasswordResetFormTag`, `__toString()` docblock correction); controllers (explicit session invalidation via new `PasswordService::destroyOtherSessions()`, ValidationController context-input hardening); client asset (auto-register on any interactivity flag, blocklist-hit propagation in zxcvbn-php engine, cpTrigger-safe fallback URL with rebuilt CP strength bundle); HIBP 429 site-wide backoff cache; dual variable handle registration; SettingsModel alias for legacy `pwned` / `pwnedFailMode` keys. P1.12 fully closed (Layer 4b + bug fixes). Phase C2 closed-closed. See `progress.md` "Session: 2026-05-02" for per-bug details.
- Manual tests: **56/57 PASS** (Phases A + B + C closed 2026-04-30; T1.2 + TX.2 + T9.7 deferred to P2.5 Pest fixtures).
- **P1 backlog: 0 items remaining (Phase C2 closed-closed).**
- P1.8 (deployment docs) moved to Phase H — Enterprise must exist before authoritative deployment docs can be written.
- P2/P3/P4: not started.
- **Release strategy:** 5.2.0 ships as a single release covering Lite + Pro + Enterprise. Nothing tags / publishes until Enterprise (Phase 10–12) is complete and tested.
- Hard gate: all Pro manual tests + all P1 items + Enterprise build (G) must pass before release prep (F).

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
- T1.2 + TX.2 — DEFERRED to P2.5 (manual fixturing too fragile; proper home is Pest tests)

### Enterprise — 6 blocked

T4.1–T4.6 (audit logging) gated on Phase 10–12.

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
| ~~P1.12~~ | ~~Pro front-end Twig surface~~ — fully closed 2026-05-01 (incl. Layer 4b strength engine unification) | Image-optimize-style fluent render builders shipped under `craft.passwordpolicy.*` (`passwordField`, `requirementList`, `strengthMeter`, `requirementsHint`, `passwordWidget`, `loginForm`, `passwordChangeForm`, `passwordResetForm`). Data accessors `requirements()` / `requirementsText()` / `requirementRules()` with optional `groups` for anonymous group preview. Vanilla-JS client asset (`PasswordPolicyClientAsset`) auto-registered by any builder with `liveValidation: true` — no Vite assumption on consumer side. Strength engine A (baseline rule-counting × length-tier) ships free on every edition; engine B (zxcvbn-php opt-in) adds score 0-4 + suggestions + crackTime on Pro. New `Front\PasswordChangeController` for logged-in change. **Layer 4b (CP-side indicator)** refactored to consume the same AJAX `/validate` endpoint the front-end builders use — single engine, blocklist-aware, per-group-aware, Pro-toggle-aware. Bundle dropped from ~1.65 MB to ~2.2 KB after `@zxcvbn-ts/*` deps were removed. The original "replace Craft's native zxcvbn meter" framing in `history/phase-c2-build-plan.md` was a spec-premise error — Craft 5 ships no client-side zxcvbn meter; the work was actually unifying the plugin's own duplicate implementation. T13.1–T13.12 in `manual-tests.md`. Full reference at `../user/features/frontend-twig.md`. |
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
| P2.1 | User index table attributes | `EVENT_REGISTER_TABLE_ATTRIBUTES` + `EVENT_SET_TABLE_ATTRIBUTE_HTML`. Columns: password status (badge), last change, expired, reset required. Lite edition. |
| P2.2 | Admin password change action | Element action with elevated session + `changedByUserId` tracking. Storage: Option A (see 6.2). New permission `pp:change-user-passwords`. Migration: nullable column on password history table. |
| ~~P2.4~~ | ~~`passwordField()` Twig function~~ — absorbed into P1.12 | Original entry was scoped narrowly to a single front-end input with strength indicator. P1.12 expands the surface to a full image-optimize-style render builder API covering field renderers + form renderers + JS asset bundle + strength engine A+B. The original deliverable becomes one method (`craft.passwordPolicy.passwordField()`) inside the larger surface. |
| P2.5 | Integration test suite | Pest scaffold exists, no test files. Validators, GroupPolicyModel merge, PolicyResolverService (incl. tri-state Option A semantics + auto-correction). |
| P2.6 | `allowAdminChanges` read-only verification | Confirm `readOnlyNotice()` banner renders and inputs disabled. |

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
- CP password field show/hide toggle (JS injection)
- Policy summary view (plain-language effective policy per user)
- CLI debug: `policy/resolve --user=<id>`, `policy/validate --user=<id> --password=<test>`

---

## 4. Build order

| Phase | Items | State |
|---|---|---|
| A | Audit fix-ups — A1 force-reset action added, A2 muteEvents applied, A3 was a non-issue, A4 UID validation added | done 2026-04-29 |
| B | Pre-release security tests — T7.3 PASS, T1.3 PASS, T1.4 PASS, TX.3 PASS, T1.2 + TX.2 deferred to P2.5 | done 2026-04-30 |
| C | Original P1 backlog — P1.2 / P1.3 / P1.4 / P1.5 / P1.7 / P1.11 done 2026-04-30. P1.8 (deployment docs) deferred to Phase H since Enterprise must exist first. | done 2026-04-30 |
| C2 | P1 expansion — Pro front-end surface bundle (P1.14 RegistrationService → P1.13 HIBP-on-login → P1.12 front-end Twig render builders + JS asset + strength engine A+B → P1.15 events catalog). | fully closed 2026-05-01 (Layer 4b strength engine unification landed in a focused session — single AJAX engine for both CP and front-end surfaces, ~1.65 MB bundle reduction) |
| D | User index integration (P2.1, P2.2) | pending |
| E | Testing infrastructure (P2.5) | pending |
| F | Polish (P2.6 — P2.4 absorbed into P1.12) | pending |
| G | Enterprise (Phase 10, 11, 12) | blocked on A+B+C+C2 |
| H | Release prep + deployment docs (P1.8) — tag 5.2.0, Plugin Store listing, marketing copy, migration guide review, deployment/cron docs (Enterprise required to write authoritative docs) | blocked on A–G |

Gates:
- B cannot start until A is complete (don't run security tests against known-broken code).
- C2 cannot start until C is complete (P1.13 builds on the email-notifications infrastructure shipped in P1.3+P1.4; P1.14 fires events that P1.15 catalogues).
- G cannot start until A+B+C+C2 are all complete (Enterprise builds on Pro foundations + finished P1 backlog + verified upgrade story).
- H cannot start until G is complete (single 5.2.0 release covers all editions; nothing tags until Enterprise is built and tested).

---

## Reference (sections 5–7) → moved

Sections 5 (completed work), 6 (settled architecture decisions) and 7 (source-code inventory) live in [`reference.md`](./reference.md). They don't change session-to-session — keeping them out of `plan.md` keeps the active plan focused on what still needs to land.

- §5.1–5.5 — phases shipped + bug fixes + features built per session → [`reference.md` §5](./reference.md#5-reference-completed-work)
- §6.1–6.7 — settled architecture decisions (compliance view, tri-state semantics, edition switching, etc.) → [`reference.md` §6](./reference.md#6-reference-architecture-decisions)
- §7.1–7.4 — current source-code inventory + integration-test edge cases → [`reference.md` §7](./reference.md#7-reference-source-code-inventory)
