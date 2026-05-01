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
