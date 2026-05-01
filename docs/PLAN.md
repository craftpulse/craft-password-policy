---
title: Password Policy v5.2.0 — Master Plan
version: 5.2.0
branch: 5.x
last_updated: 2026-05-01
status:
  pro_ui: feature_complete
  manual_tests: 56/57 PASS (T1.2 + TX.2 + T9.7 deferred)
  p1_remaining: 4 (P1.12 front-end Twig surface, P1.13 HIBP-on-login, P1.14 RegistrationService, P1.15 events catalog)
  p2_remaining: 4 (P2.4 absorbed into P1.12)
  enterprise: not_started
release_strategy: single_5_2_0_includes_all_editions
gate: enterprise_must_complete_before_release_prep
read_order_active: [1, 2, 3, 4]
read_order_reference: [5, 6, 7]
---

# Password Policy v5.2.0 — Master Plan

Master plan for the v5.2.0 Pro/Enterprise expansion. Sections 1–4 cover active work. Sections 5–7 are reference for completed history, settled architecture decisions, and source-code inventory. Skip 5–7 unless investigating prior context.

## Contents

| # | Section | State |
|---|---|---|
| 1 | [Status](#1-status) | active |
| 2 | [Manual testing remaining](#2-manual-testing-remaining) | done — 56/57 PASS, 3 deferred to P2.5 (T1.2 + TX.2 + T9.7) |
| 3 | [Backlog](#3-backlog) | active |
| 4 | [Build order](#4-build-order) | active |
| 5 | [Reference: completed work](#5-reference-completed-work) | done, skippable |
| 6 | [Reference: architecture decisions](#6-reference-architecture-decisions) | settled, skippable |
| 7 | [Reference: source code inventory](#7-reference-source-code-inventory) | snapshot, skippable |

State legend: `active` = read now, `pending` = scheduled, `done` = built, `blocked` = gated, `settled` = decided.

---

## 1. Status

- 10 alpha/beta branches merged into `5.x`, plus end-of-Phase-C work (P1.3 + P1.4 paired Email Notifications, P1.7 retention UI, P1.11 blocklist editor, P1.5 group-deletion listener) shipped on 5.x directly.
- Pro CP UI feature-complete: named-policy CRUD with presets + tri-state + divergence indicators + conflict UX, env-var inputs, blocklist subnav with custom dictionary editor + word-check tool, retention page with `notificationLogRetentionDays`, **Email Notifications subnav with token picker + per-(key, siteId) editing + sender overrides + AJAX test-send**, group-deletion observability listener, force-reset action.
- **Pro front-end Twig surface — partial today, full build specced for Phase C2.** `PasswordPolicyVariable` exposes status helpers (`daysUntilExpiry`, `isExpired`, `isExpiring`, `passwordStatus`, `lastPasswordChange`, `activeSessionCount`) and `ValidationController::actionValidate` is `$allowAnonymous` for AJAX use. **P1.12** (locked 2026-05-01) ships the full surface: image-optimize-style fluent render builders for fields (`passwordField`, `requirementList`, `strengthMeter`, `requirementsHint`, `passwordWidget`) + forms (`loginForm`, `passwordChangeForm`, `passwordResetForm`), data accessors (`requirements`, `requirementsText`, `requirementRules`), JS asset bundle (no Vite dep on consumer side), strength engine A baseline + B Pro opt-in (`bjeavons/zxcvbn-php`, approved 2026-05-01), a11y baseline, show/hide toggle. P2.4 is absorbed.
- Manual tests: **56/57 PASS** (Phases A + B + C closed 2026-04-30; T1.2 + TX.2 + T9.7 deferred to P2.5 Pest fixtures).
- **P1 backlog: 4 items remaining (Phase C2)** — P1.12 (Pro front-end Twig surface), P1.13 (HIBP-on-login Pro), P1.14 (RegistrationService Lite + Pro per-group validation), P1.15 (events catalog + `docs/events.md`).
- P1.8 (deployment docs) moved to Phase H — Enterprise must exist before authoritative deployment docs can be written.
- P2/P3/P4: not started.
- **Release strategy:** 5.2.0 ships as a single release covering Lite + Pro + Enterprise. Nothing tags / publishes until Enterprise (Phase 10–12) is complete and tested.
- Hard gate: all Pro manual tests + all P1 items (incl. P1.12 once approved) + Enterprise build (G) must pass before release prep (F).

---

## 2. Manual testing remaining

Per-test results in `docs/TESTING.md`. Phases A + B closed; nothing remains in this section that's not gated on Enterprise.

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
| P1.12 | Pro front-end Twig surface — render builders + JS asset + strength engine | Image-optimize-style fluent builder API on `craft.passwordPolicy.*` for building user-facing login/registration/reset/change-password pages. **Field renderers**: `passwordField()`, `requirementList()`, `strengthMeter()`, `requirementsHint()`, `passwordWidget()` (composite — input + meter + checklist + hint). **Form renderers**: `loginForm()` (POSTs to Craft `users/login`), `passwordChangeForm()` (logged-in user, POSTs to a new `Front\PasswordChangeController`), `passwordResetForm()` (token-based reset, POSTs to a new `Front\PasswordResetController`). `registrationForm()` deliberately NOT shipped — consumers compose `passwordField()` + `requirementList()` into their own form (full Formie-style form engine = 5.3 roadmap). **Data accessors** (always available): `requirements(['groups' => ['editors']])` returns the resolved policy as a flat typed array (Lite returns global; Pro resolves per-group, anonymous can preview-by-group), `requirementsText()` returns a single human-readable summary string, `requirementRules()` returns `[{key, label, met?}]` for devs rendering bespoke checklists. **Renderer ergonomics**: every builder mirrors image-optimize — chained setters (`.name().id().inputAttrs({...}).render()`) AND equivalent config-object form (`passwordField({name: '...', inputAttrs: {...}}).render()`); `*Attrs()` setters per element (`inputAttrs`, `wrapperAttrs`, `toggleAttrs`, `formAttrs`, `submitButtonAttrs`, etc.) merge into the rendered markup; empty values omitted from output. **a11y baked in** (non-negotiable, plugin's responsibility): live region, `aria-describedby` linking input to requirements list, `aria-invalid` toggled on validation state, `aria-busy` during HIBP-pending, screen-reader announcements for pass/fail transitions. **Show/hide toggle**: default ON, per-builder opt-out via `.toggleVisibility(false)`, FA-style eye/eye-slash inline SVG (MIT path data, no asset dep). **Strength engine — A baseline + B Pro opt-in, applies front-end + CP**: A always on (rule-counting × length-tier label `weak/fair/strong/excellent`, plus blocklist-hit forces "weak"), no client deps. B opt-in via plugin setting `useZxcvbnStrength: true` (default off) — adds `bjeavons/zxcvbn-php` composer dep (~200KB minus dictionaries, MIT, approved 2026-05-01); `ValidationController::actionValidate` returns additional `{strength: {score: 0..4, label, suggestions: [], crackTime: '...'}}` payload when enabled. **Engine replaces Craft's native zxcvbn-js meter on the CP for Pro installs** (admin account password change, new-user creation, plugin password fields) — single source of truth for strength UX everywhere. New `PasswordPolicyCpStrengthAsset` registered only on Pro CP requests. Lite installs keep Craft's native meter untouched (asymmetry serves as upgrade incentive). CP integration preserves Craft's submit-gating (never allow weaker passwords through than Craft would have). **Distribution**: pre-built JS lives in `src/web/assets/dist/password-policy.js` (vanilla, framework-free, ~5KB minified, **no Vite assumption** for consumers). `PasswordPolicyClientAsset extends \craft\web\AssetBundle`, auto-registered when any builder is called with `liveValidation: true`. JS attaches to `[data-pp-validate]`, debounced 250ms, POSTs to `validation/validate`, toggles classes on consumer slots. **HIBP UX**: non-blocking submit (validate returns null for HIBP-pending; submit gate clears on synchronous rules, flips to fail when HIBP comes back as breached). **Edition gating**: methods callable on Lite (return global resolution), Pro adds per-group resolution via `PolicyResolverService`; no edition-strip silent failures. **Naming**: absorbs and supersedes legacy P2.4 entry. |
| P1.13 | HIBP-on-login (Pro) | Login event listener (`User::EVENT_AFTER_LOGIN` — verify exact name against Craft 5 user component) hashes the plaintext (still in scope at the login window) to SHA-1, k-anonymity prefix lookup against HIBP API, async (never blocks login). 24h dedup cache via `Craft::$app->cache` (key shape: `pp:hibp-login:<userId>:<sha1Prefix>`) — avoids hammering HIBP for daily-active users. **On detection**: (a) set `passwordResetRequired = true` on the User; (b) send `breach-detected` notification email via `NotificationService` (new notification key in `EmailDefaults`, eager-seeded into `passwordpolicy_notification_templates` for every enabled site at upgrade time + via the existing `Sites::EVENT_AFTER_SAVE_SITE` propagation listener); (c) log to Enterprise audit log via `AuditLogService->logEvent('breach_detected', ...)` — Enterprise-tier observability, audit log table already exists; (d) fire new `BreachDetectedEvent` for consumer hooks. **Privacy**: never log the plaintext, hash, or prefix — only the SHA-1 prefix's HIBP "match found" boolean + a redacted user ID. **Failure modes**: HIBP API down → silent fail + retry next login; rate-limited → respect `retry-after` header. **Setting**: new Pro setting `enableHibpOnLogin: bool` (default `true` once admin upgrades to Pro). **Edition**: Pro-only — listener registers only when `getIsPro()`. |
| P1.14 | Registration helper service (Lite + Pro per-group validation) | New `RegistrationService::register(array $params): User`. Params: `email` (required), `password` (required), `username` (optional, defaults to email), `groups` (array of group **handles**, looked up at call time — more dev-friendly than IDs), `fields` (custom field values keyed by handle), `sendActivationEmail` (default true if Craft requires activation). **Pre-validates password** against the resolved policy (Lite = global; Pro = per-group resolution against the assigned `groups` param using `PolicyResolverService`). **On success**: creates the user via `Craft::$app->elements->saveElement()`, assigns groups via `Craft::$app->users->assignUserToGroups()`, sets custom field values, optionally sends activation email, fires new `UserRegisteredEvent` (`user`, `groups`, `viaService: true`). **On failure**: throws `ValidationException` with `getValidationErrors()` for per-field surfacing. Service registered in `ServicesTrait` as `registration`. **Edition**: Lite baseline (basic registration, global policy validation). Pro layers in per-group policy resolution against the assigned groups (so a registration form for "Sign up as Editor" pre-validates against the Editors policy). Same shape as `requirements()` — methods don't fail on Lite, they degrade to global. Used internally by future `registrationForm()` (5.3); also exposed for consumers' own registration controllers. |
| P1.15 | Event catalog + documentation (Lite, infrastructure) | New `docs/events.md` documenting every event the plugin fires, with: name, fully-qualified class, when fired, payload shape (typed properties), example listener with imports. Cross-linked from `README.md` ("Events" section) and the Plugin Store description (events are a Pro positioning point). **Catalogued for 5.2.0**: `PasswordChangedEvent` (Lite, already shipped), `UserRegisteredEvent` (Lite, P1.14), `BreachDetectedEvent` (Pro, P1.13). **Cross-cutting build rule**: every new feature ships with its event class defined and its `docs/events.md` row added in the same commit — events drift from documentation otherwise. Future events (5.3+ or Phase G): `PolicyValidatedEvent`, `PasswordExpiredEvent`, `LockoutThresholdReachedEvent` (Enterprise). Each event class gets full PHPDoc with `@event` markup so IDE tooling surfaces it. Section headers with `=========` separators per the project's PHP guidelines. |

### P1: shipped (this session)

- P1.1 — manual testing tracking (moved to TESTING.md)
- P1.6 — group policies CP UI (named-policies CRUD, see `docs/05-per-group-policies.md`)
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
| Phase 11 | Compliance dashboard | ComplianceDashboardUtility (aggregates), ReportController (HTML/PDF/CSV export), compliance mapping, PCI-DSS tension. **Includes:** CP-wide policy conflict alert via `Cp::EVENT_REGISTER_ALERTS` — surfaces conflicts on every CP page (Pro/Lite get P1.9 + P1.10 only, Enterprise adds this). |
| Phase 12 | SIEM + webhooks + API tokens | SiemService, WebhookService, ApiTokenService, ApiController, SiemForwardJob, circuit breaker, HMAC-SHA256 webhook signatures. |
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
| C2 | P1 expansion — Pro front-end surface bundle (P1.14 RegistrationService → P1.13 HIBP-on-login → P1.12 front-end Twig render builders + JS asset + strength engine A+B → P1.15 events catalog). Build order has small foundations first (event classes + RegistrationService), then HIBP infra (adds `breach-detected` notification key + audit hook), then the large front-end surface, then docs synthesizing all events. | next |
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

## 5. Reference: completed work

> Skippable unless investigating prior decisions or commit history.

### 5.1 Phases shipped

| Phase | Branch | Summary |
|---|---|---|
| 0 | alpha.1 | Edition infrastructure, settings model, HIBP TLS fix, log key stripping |
| 1 | alpha.2 | Install + upgrade migrations, 4 records, 4 tables, history seeding |
| 2 | alpha.3 | PasswordHistoryService, PasswordHistoryValidator, event handlers, recursion guard |
| 3 | alpha.4 | 5 validators, BlocklistService, BlocklistController (console), common-passwords data |
| 4 | alpha.5 | AuditLogService, AuditController (console), Craft security listeners, HIBP fail-mode |
| 5 | beta.1 | GroupPolicyModel, PolicyPreset enum, PolicyResolverService |
| 6 | beta.2 | 3 condition rules, ForcePasswordReset action, password-security.twig |
| 7 | beta.5 | Settings UI, blocklist dedup fix, info tooltips, BlocklistUtility, SeedBlocklist job |
| 8 | beta.3 | PasswordChangedEvent, session invalidation, group force reset |
| 9 | beta.4 | NotificationService, GC hook, ValidationController (AJAX), Twig variables |
| - | 5.x (this session) | Named policies CRUD, tabbed edit screen, tri-state UI, divergence indicators, resolver bool refactor (Option A), per-user UserRules resolution |

### 5.2 Bug fixes (this session, uncommitted)

- Orphan `expiryPeriod` strip when no `expiryAmount`
- Preset JS↔PHP value sync (NIST/OWASP/PCI presets had spurious explicit-Off in JS)
- Tri-state preset auto-fill via Craft's Lightswitch API
- Override warnings only render when value differs from global
- `[hidden]` CSS override (Craft's `.warning.has-icon` flex)
- `setSettingsFromArray` resets fields to null first
- `forms.checkboxSelectField` empty-string coercion in `actionSave`
- Model-level minLength ≤ maxLength validation (self-collision caught at save)
- `UserRules::defineRules()` now consults `PolicyResolverService::resolveForUser($user)` instead of global settings
- `ValidationController` AJAX endpoint also resolves per-user
- `maxLength > minLength` rule guard widened to `> 0` after auto-correction redesign
- Auto-correction redesign: `maxLength = minLength` (exact-length-only) replaced with `maxLength = 0` (cap dropped) on conflict

### 5.3 Bug fixes (earlier session, committed)

- `getIsLite()` hardcoded to `true` (`43c6f6c`)
- Validation order: content rules before HIBP/history (`43c6f6c`)
- "1 of 4" useless dropdown option (`43c6f6c`)
- Number-input width on retention page (`43c6f6c`)
- Edition gate upgrade-link icon (`43c6f6c`)
- PCI compliance link (`43c6f6c`)
- History instructions mdash (`43c6f6c`)
- Blocklist auto-seed via queue (`fb3e9b3`)
- `lastPasswordChangeDate` direct query (`bc6196d`)

### 5.4 Features built (this session, uncommitted)

1. Named policies CRUD (PolicyController, PolicyService, PolicyModel, PolicyRecord, PolicyGroupRecord, edit/index templates, migration `m260426_000000_AddPoliciesTables`)
2. Tabbed edit screen via `asCpScreen()->tabs()` (General / Rules / Lifecycle)
3. Tri-state rule overrides (Off / Global / On) — webhook plugin pattern
4. Override warnings via `forms.field` `warning:` parameter (Blitz pattern with `_macros.twig`)
5. Divergence indicators (blue dot in index, blue left border on edit fields, "Changes" column with count)
6. "Restore preset defaults" button (re-applies preset values via JS)
7. "Reset all to global" button in toolbar (`additionalButtonsHtml`)
8. PolicyResolverService two-phase bool merge (any-true wins, then any-false wins, then global)
9. PolicyModel `getDivergentFields()` and `getOverrideFields()` helpers
10. Per-user policy resolution at validation time (UserRules + ValidationController)

### 5.5 Features built (earlier session, committed)

- Custom CP icons for password policy nav
- Info icon tooltips on settings pages (NIST/PCI-DSS/GDPR references)
- BlocklistUtility (CP utility, stats, "Update Common Passwords" button, `pp:blocklist-manage` permission)
- SeedBlocklist queue job + auto-seed trigger when toggle enabled with empty blocklist
- Fail-closed JS warning on HIBP fail-mode dropdown

---

## 6. Reference: architecture decisions

> Skippable unless ambiguity arises about a previously-decided approach.

### 6.1 Compliance view (Phase 11) — hybrid

Extend Users index for day-to-day work + ComplianceDashboardUtility for reporting.

- Users index: table attributes (P2.1), condition rules (built — 3 rules), bulk actions (built — ForcePasswordReset)
- ComplianceDashboardUtility: aggregate metrics, framework mapping (NIST/OWASP/PCI-DSS green/amber/red), CSV/PDF export, drill-down to Users index
- Rejected: custom CP section (duplicates Users index)

### 6.2 P2.2 admin password change — `changedByUserId` storage (Option A)

Tension: `changedByUserId` exists on audit log table, audit logging is Enterprise-gated.

- A (chosen): store on password history table (all editions). Not exposed via UI/API on non-Enterprise. Enterprise audit log JOINs to it.
- B (rejected): always write audit log entry on Pro, gate UI/export. Risk: data leakage via direct DB query.
- C (subset of A): never write audit log entry on non-Enterprise. Cleanest separation.

### 6.3 Tri-state override semantics — Option A (built)

For boolean overrides per-policy:

- Single group's explicit `false` is honored against global `true` (single-group exemption)
- Multi-group resolution: any explicit `true` wins over any explicit `false` (most-restrictive wins)
- Implementation: PolicyResolverService two-phase merge (bool pre-pass + non-bool sequential)

### 6.4 maxLength vs minLength conflict (built)

When merge produces `maxLength < minLength`, drop the maxLength cap (set to 0 / no limit).

- Reasoning: minLength is security-critical (never weaken), maxLength is defensive only
- Logged as `WARNING`. Surfaced via P1.9 (save-time notice) and P1.10 (edit-screen banner)
- Rejected alternative: `maxLength = minLength` (creates bizarre exact-length-only behavior)

### 6.5 Edition switching

`project.yaml` (`plugins.password-policy.edition: pro`) + update `dateModified` + `ddev craft up`. Do NOT use `app.php` `pluginConfigs` hacks.

### 6.6 Multi-site

Craft users live at install level, not per-site. No multi-site edge cases for password policies.

### 6.7 Sequential validator case-insensitivity

Lowercase before scanning. `pqR`/`Pqr`/`PQR` all trigger on `pqr` sequence. Matches zxcvbn / hashcat-rules thinking — case-mixed variants of a sequence provide no meaningful additional strength against real attackers.

---

## 7. Reference: source code inventory

> Skippable unless unsure what already exists.

### 7.1 Counts

- Services: 9
- Web controllers: 5
- Console controllers: 3
- Validators: 7
- Utilities: 2
- Jobs: 2
- Condition rules: 3
- Element actions: 1
- Events: 1
- Permissions: 3 + 1 planned

### 7.2 By component

| Type | Names |
|---|---|
| Services | AuditLogService, BlocklistService, NotificationService, PasswordHistoryService, PasswordService, PolicyResolverService, PolicyService, RetentionService, SecurityService |
| Web controllers | SettingsController, ValidationController, BlocklistController, RetentionController, PolicyController |
| Console controllers | BlocklistController, AuditController, GcController |
| Models | PolicyModel, GroupPolicyModel, SettingsModel |
| Records | PolicyRecord, PolicyGroupRecord |
| Validators | HibpValidator, SequentialCharsValidator, RepeatedCharsValidator, ContextualValidator, CommonPasswordValidator, MinimumCharacterTypesValidator, PasswordHistoryValidator |
| Utilities | RetentionUtility (Lite), BlocklistUtility (Pro) |
| Jobs | PasswordResetJob, SeedBlocklist |
| Condition rules | PasswordExpiredConditionRule, PasswordResetRequiredConditionRule, PasswordNeverChangedConditionRule |
| Element actions | ForcePasswordReset (Pro) |
| Events | PasswordChangedEvent (Lite — free for ecosystem) |
| Permissions | `pp:settings`, `pp:force-reset-passwords`, `pp:blocklist-manage`, `pp:change-user-passwords` (planned for P2.2) |

### 7.3 Settings without UI

`adminAlertEvents`, all SIEM settings, all webhook settings, `enableNewDeviceAlerts`, `deviceRetentionDays`, `notificationLogRetentionDays`. Wired into model + validation, not yet rendered. P1.7 covers `notificationLogRetentionDays`. Others wait for Phase 10–12.

### 7.4 Edge cases for P2.5 integration tests

1. Queue worker site context for GC and SeedBlocklist jobs
2. Concurrent password changes (race condition in history save)
3. GraphQL mutation password changes — confirm plugin events fire
4. `passwordHistoryCount` validator class instantiation on Lite if setting > 0 (validator gates internally; confirm class isn't loaded unnecessarily)
