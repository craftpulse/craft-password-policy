---
title: Password Policy v5.2.0 — Plan Reference (Completed Work + Architecture + Inventory)
version: 5.2.0
branch: 5.x
last_updated: 2026-05-02
purpose: reference companion to plan.md (sections 5–7)
read_when: investigating prior decisions, settled architecture, or what already exists
---

# Password Policy v5.2.0 — Plan Reference

This file is the reference companion to [`plan.md`](./plan.md). It carries the historical context (sections 5–7 of the original PLAN.md) that doesn't change session-to-session:

- Section 5 — completed work history
- Section 6 — settled architecture decisions
- Section 7 — source-code inventory snapshot

`plan.md` is for active work (status, manual-test gaps, backlog, build order). This file is for "what's already shipped, what's already decided, what already exists." Skip unless investigating prior context.

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
| - | 5.x (Phase C2) | Named policies CRUD, tabbed edit screen, tri-state UI, divergence indicators, resolver bool refactor (Option A), per-user UserRules resolution; Pro front-end Twig surface (P1.12 fluent builders + Layer 4b strength engine unification); HIBP-on-login (P1.13); RegistrationService (P1.14); events catalog (P1.15); 11-bug code-review sweep |
| E | 5.x (Phase E, 2026-05-02) | Pest test infrastructure — 18 commits + `fix(hibp)` + `docs(ideas)`. Custom Pest bootstrap (no Codeception), dedicated `db_test` MySQL DB, `MigrationTestCase` + `MultiSiteTestCase` non-transactional bases, six factories + four stubs. `HibpClientInterface` extracted from `PasswordService` for testability. Coverage: validators (5), services (5), models (2), controllers (2), Twig tags (1), migrations (T1.2 + TX.2), multi-site (T9.7). 329 passing / 0 skipped / 634 assertions. Five new skill gaps (#15–19) captured. See `history/progress-phase-e.md` for full detail. |
| D | 5.x (Phase D, 2026-05-03) | User index integration — 19 commits across D0–D4. **D0** audit context surface (`ChangeReason` enum, `AuditContext` model, `UserStateService`, audit-shape migration adding `changeReason`/`changedByUserId`/`changedFromIp`/`changedFromUserAgent` columns + new `passwordpolicy_user_state` table). **D1** central history-listener wiring (three-tier explicit > pending-reason > default precedence; force-reset, expiry, HIBP, first-login pin pending reasons that next save consumes). **D2** user-index columns + condition rules (`UserIndexService` with bounded-query preload contract; six Lite-tier columns + three Pro-tier columns gated on Craft Team or higher; composite seven-state status priority; five new condition rules). **D3** admin element actions (`ChangeUserPassword`, `SendPasswordResetEmail`) + `UserPasswordController` (CP POST, elevated session, policy-validation gate, explicit-context propagation) + new `pp:change-user-passwords` permission. **D4** user-edit "tab" via sidebar pointer (`Element::EVENT_DEFINE_SIDEBAR_HTML` — Craft 5 has no native top-level tab event; sidebar is the closest idiomatic surface) + `UserSecurityController` rendering the half-built `_users/password-security.twig` template. P2.6 verification gate satisfied throughout — every CP affordance respects `allowAdminChanges = false`. 513 passing / 0 skipped / 1049 assertions (+184). One new skill gap (#20 — console-bootstrap CP-test trifecta) captured. See `history/progress-phase-d.md` for full detail. |

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

### 6.8 User-edit "tab" is a sidebar pointer, not a top-level tab (Phase D4)

Craft 5 doesn't expose a public event for plugins to register top-level tabs on the User edit screen. Tabs come from the field layout (admin-editable) plus the controller-owned `CpScreenResponseBehavior::tabs()` slot — neither extensible by plugins. Verified by reading `craft\elements\User`, `craft\controllers\ElementsController::actionEdit`, `craft\helpers\Cp`, `craft\web\View`, and the entire `vendor/craftcms/cms/src/templates` Twig hook surface. The Craft 3-era `cp.users.edit` hook isn't there; the historical `users/_edit.twig` template doesn't exist either.

The closest idiomatic surface is `Element::EVENT_DEFINE_SIDEBAR_HTML` on the User class, which appends to the right-side meta-fields column. Phase D4's "Password Security" pointer registers there, linking to a standalone CP page (`password-policy/users/<userId>/security`) rendered by `UserSecurityController`. The link is gated either-or on `pp:force-reset-passwords` OR `pp:change-user-passwords` (single source of truth: `UserSecurityController::callerHasViewPermission()`).

If a future Craft release adds a tab-injection event, swap the registration listener — the controller, URL rule, and template stay unchanged.

---

## 7. Reference: source code inventory

> Skippable unless unsure what already exists.

### 7.1 Counts

- Services: 17
- Web controllers: 8 + 1 front-end
- Console controllers: 5
- Validators: 7
- Utilities: 1
- Jobs: 3
- Condition rules: 8
- Element actions: 3
- Events: 4
- Permissions: 5

### 7.2 By component

| Type | Names |
|---|---|
| Services | AuditLogService, BlocklistService, GuzzleHibpClient, HibpClientInterface, NotificationService, NotificationTemplateService, PasswordHistoryService, PasswordService, PolicyResolverService, PolicyService, RegistrationService, RetentionService, SecurityService, StrengthService, UserIndexService, UserStateService (+ ServicesTrait) |
| Web controllers | BlocklistController, NotificationTemplateController, PolicyController, RetentionController, SettingsController, UserPasswordController, UserSecurityController, ValidationController + front/PasswordChangeController |
| Console controllers | AuditController, BlocklistController, GcController, NotificationController, RetentionController |
| Models | AuditContext, GroupPolicyModel, NotificationTemplateModel, PolicyModel, SettingsModel |
| Records | AuditLogRecord, BlocklistWordRecord, NotificationLogRecord, NotificationTemplateRecord, PasswordHistoryRecord, PolicyGroupRecord, PolicyRecord, UserStateRecord |
| Validators | CommonPasswordValidator, ContextualValidator, HibpValidator, MinimumCharacterTypesValidator, PasswordHistoryValidator, RepeatedCharsValidator, SequentialCharsValidator |
| Utilities | RetentionUtility (Lite) — BlocklistUtility removed in Phase C2 (functionality moved to `/admin/password-policy/blocklist` subnav) |
| Jobs | PasswordResetJob, SeedBlocklist, SendPasswordExpiryRemindersJob |
| Condition rules | BreachedRecentlyConditionRule (Pro), LastChangeReasonConditionRule, PasswordExpiredConditionRule, PasswordExpiringWithinConditionRule, PasswordNeverChangedConditionRule, PasswordResetRequiredConditionRule, PasswordStatusConditionRule, PolicyDriftConditionRule (Pro + Craft Team+) |
| Element actions | ChangeUserPassword (all editions), ForcePasswordReset (Pro), SendPasswordResetEmail (all editions) |
| Events | BreachDetectedEvent (Pro), PasswordChangedEvent (Lite), PasswordValidationEvent (Lite — wired in Phase F polish), UserRegisteredEvent (Lite) |
| Enums | ChangeReason, PolicyPreset |
| Permissions | `pp:settings`, `pp:force-reset-passwords`, `pp:change-user-passwords`, `pp:blocklist-view`/`pp:blocklist-manage`, `pp:notification-templates-manage` |

### 7.3 Settings without UI

All SIEM settings, all webhook settings, `enableNewDeviceAlerts`, `deviceRetentionDays`, `auditLogRetentionDays`, `adminAlertEmail`, `adminAlertEvents`, `apiEnabled`. Wired into the model + validation; render in Phase G alongside the Enterprise audit / SIEM / webhooks features.

`notificationLogRetentionDays` (P1.7), `expiryReminderDays` (P1.7), `enableAuditLog` (P1.6), and `useZxcvbnStrength` (Phase F polish) all have UI now.

### 7.4 Edge cases for P2.5 integration tests — status post-Phase-E

P2.5 closed as Phase E (2026-05-02). The four edge cases enumerated when this section was first written:

1. **Queue worker site context for GC and SeedBlocklist jobs** — NOT covered in Phase E. Worth adding when queue-job tests come online (likely Phase G or a 5.2.x follow-up).
2. **Concurrent password changes (race condition in history save)** — NOT covered in Phase E (Pest tests are sequential per process; concurrent-write scenarios need a different harness — probably benchmark-style or a Codeception-feature equivalent). Captured for the Adversarial Test Suite in `ideas.md`.
3. **GraphQL mutation password changes — confirm plugin events fire** — NOT covered in Phase E (no GraphQL tests in scope; P3+ follow-up).
4. **`passwordHistoryCount` validator class instantiation on Lite if setting > 0** — NOT explicitly covered; `PasswordHistoryValidator` tests in E3 codify the validator's internal Pro-edition gate. The class-loading concern is best caught by static analysis or a future micro-benchmark.

### 7.5 Pest test surface (post-Phase D, 2026-05-03)

| Type | Count | Notes |
|---|---|---|
| Test files | 36 | `tests/Unit/`, `tests/Integration/{Validators,Services,Models,Records,Controllers,TwigTags,Migrations,MultiSite,ConditionRules,UserIndex,UserEditTab}/` |
| Tests | 513 | 0 skipped (+184 over Phase E baseline) |
| Assertions | 1049 | (+415 over Phase E baseline) |
| Factories | 6 | UserFactory (with `nonAdmin()` added in D), GroupFactory, PolicyFactory, BlocklistFactory, PasswordHistoryFactory, SessionFactory |
| Stubs / fakes | 4 | HibpClientFake, WebRequestStub (extended in D with `getPathInfo()` + `getUrl()`), UserStub (extended in D with `stubHasElevatedSession`), TestGuzzleConfig |
| Base test cases | 3 | TestCase (transaction wrap), MigrationTestCase (DDL teardown), MultiSiteTestCase (site cleanup) |

Phase D added 18 new test files (`Integration/ConditionRules/` × 5, `Integration/UserIndex/` × 8, `Integration/UserEditTab/` × 1, plus four new `Integration/Services/` files for audit-context propagation, `Integration/Records/UserStateRecordTest.php`, and `Integration/Controllers/UserPasswordControllerTest.php`). The bounded-query contract for `UserIndexService::preloadForUsers()` is pinned by `PreloadBatchingTest` — refactor regressions on the preload surface fail loudly in CI.

Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`. Chains ECS → PHPStan → Pest; first failure stops the chain.
