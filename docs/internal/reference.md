---
title: Password Policy v5.2.0 — Plan Reference (Completed Work + Architecture + Inventory)
version: 5.2.0
branch: 5.x
last_updated: 2026-05-18
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

| Phase | Branch / Span | Summary |
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
| C2 | 5.x (2026-05-01) | Named policies CRUD, tabbed edit screen, tri-state UI, divergence indicators, resolver bool refactor (Option A), per-user UserRules resolution; Pro front-end Twig surface (P1.12 fluent builders + Layer 4b strength engine unification); HIBP-on-login (P1.13); RegistrationService (P1.14); events catalog (P1.15); 11-bug code-review sweep |
| E | 5.x (2026-05-02) | Pest test infrastructure — 18 commits + `fix(hibp)` + `docs(ideas)`. Custom Pest bootstrap, dedicated `db_test` MySQL DB, `MigrationTestCase` + `MultiSiteTestCase` non-transactional bases, six factories + four stubs. `HibpClientInterface` extracted. 329 passing / 0 skipped / 634 assertions. See `history/progress-phase-e.md`. |
| D | 5.x (2026-05-03) | User index integration — 19 commits across D0–D4. Audit context surface (`ChangeReason`, `AuditContext`, `UserStateService`), audit listener wiring (three-tier explicit > pending-reason > default), user-index columns + condition rules, admin element actions + `UserPasswordController`, user-edit "tab" via sidebar pointer + `UserSecurityController`. 513 passing / 1049 assertions. P2.6 verification gate satisfied throughout. See `history/progress-phase-d.md`. |
| F + F2 + F3 | 5.x (2026-05-06) | UI sweep (status pills via `Cp::statusLabelHtml()`, expiry-gated columns, `EVENT_DEFINE_EDIT_SCREENS` replacing D's sidebar workaround, action-menu listener); notifications activity surface P2.9 (capture-on-failure + resend + per-user panel; `passwordpolicy_notification_log` schema rewrite); Phase G build plan P2.8 → [`phase-g-build-plan.md`](./phase-g-build-plan.md) (1238 lines, G1–G12). 551 passing / 1151 assertions. See `history/progress-phase-f.md`. |
| G | 5.x (2026-05-07 → 14) | Enterprise build — G1–G12 + post-review remediation Steps 1–8. Twelve features (hash-chained audit log, verifier CLI, compliance dashboard, policy-change diffs, PII allowlist, per-policy custom blocklist, AlertCooldownService, syslog-over-TLS SIEM forwarder, signed webhook forwarder, streaming audit export, custom email template paths, Enterprise notification keys). Three record→element refactors (NotificationLog, AuditLog, Policy). 17K+ lines. 786 passing / 1875 assertions. Schema 2.4.0 → 2.11.0. See `history/progress-phase-g.md`. |
| Phase H prep | 5.x (2026-05-14 → 15) | Security audit polish (15 single-issue commits + P2 + P3 bundles — authorization scopes, info disclosure, secret stripping, cache-key privacy); Phase 2 edition realignment (password history universal, four compliance presets universal, expiry-reminder email universal, CIS Controls v8 preset added); comprehensive `docs/user/` rewrite for 5.2.0 ship state; 5.3 candidate bundle recorded in `ideas.md`. ~35 commits. 802 passing / 1924 assertions. Schema unchanged at 2.11.0. See `history/progress-phase-h-prep.md`. |
| H | 5.x (from 2026-05-18) | Release prep + full QA pass. Manual test register T14.x–T25.x authored. End-to-end QA walkthrough. Plugin Store listing rewrite. Marketing copy. Tag 5.2.0 (composer.json stays at `5.2.0-alpha.1` per user direction). **In flight.** |

### 5.2 5.1.x maintenance line

`5.1.2` tagged 2026-05-02 (`833a038`), pushed to origin. Three backports — TLS verify (`e58f0d7`), fail-open log level (`dbe050c`), sensitive-key strip (`b85a6c9`). Channel idle until a new security signal warrants 5.1.3 — post-5.1.2 5.x fixes all target 5.2.0-only surfaces.

### 5.3 Earlier-session bug fixes (5.x cumulative, committed)

- `getIsLite()` hardcoded to `true` (`43c6f6c`)
- Validation order: content rules before HIBP/history (`43c6f6c`)
- "1 of 4" useless dropdown option (`43c6f6c`)
- Number-input width on retention page (`43c6f6c`)
- Edition gate upgrade-link icon (`43c6f6c`)
- PCI compliance link (`43c6f6c`)
- History instructions mdash (`43c6f6c`)
- Blocklist auto-seed via queue (`fb3e9b3`)
- `lastPasswordChangeDate` direct query (`bc6196d`)

---

## 6. Reference: architecture decisions

> Skippable unless ambiguity arises about a previously-decided approach.

### 6.1 Compliance view (Phase G) — hybrid surface

Extend Users index for day-to-day work + `ComplianceDashboardUtility` for reporting. Built per Phase D + G:

- Users index: table attributes (P2.1), condition rules (8 rules), bulk actions (ForcePasswordReset; ChangeUserPassword + SendPasswordResetEmail registered via `EVENT_DEFINE_ACTION_MENU_ITEMS` per user)
- `ComplianceDashboardUtility`: aggregate metrics, framework mapping (NIST/OWASP/PCI-DSS/CIS/Strict Enterprise), HTML + CSV reports via `ReportController`, framework anchors documented in `docs/user/operations/compliance-frameworks.md`
- Rejected: custom CP section (duplicates Users index)

### 6.2 Audit capture principle — capture on every edition, gate exposure

Codified in Phase F2 (`project_audit_capture_principle.md`). Lite + Pro + Enterprise all populate audit columns on `passwordpolicy_password_history` and `passwordpolicy_notification_log`; Enterprise alone surfaces the full `passwordpolicy_audit_log` chain through the CP. Upgrading from Lite to Pro to Enterprise retains the full history rather than starting from scratch on each upgrade.

This principle expanded in the 2026-05-15 Phase 2 edition realignment from "capture audit data on every edition" to "enforce security-critical mechanisms on every edition" (history + presets + expiry email).

### 6.3 Foundation-first, no refactor deferrals

Codified in `feedback_foundation_first_no_refactor_deferrals.md`. Foundation correctness ships in 5.2.0 — only deferrals that build ON 5.2.0 go to 5.3+, never major refactors of shipped surfaces. Drove the three record→element refactors in Phase G post-review remediation (NotificationLog, AuditLog, Policy) — landing them post-tag would have required severe migration code at the 5.3 boundary.

### 6.4 Tri-state override semantics — Option A (built)

For boolean overrides per-policy:

- Single group's explicit `false` is honored against global `true` (single-group exemption)
- Multi-group resolution: any explicit `true` wins over any explicit `false` (most-restrictive wins)
- Implementation: `PolicyResolverService` two-phase merge (bool pre-pass + non-bool sequential)

### 6.5 maxLength vs minLength conflict

When merge produces `maxLength < minLength`, drop the maxLength cap (set to 0 / no limit). Logged as `WARNING`. Surfaced via save-time notice (P1.9) + edit-screen banner (P1.10).

### 6.6 Edition switching

`project.yaml` (`plugins.password-policy.settings.edition: enterprise|pro|lite`) + update `dateModified` + `ddev craft up`. Do NOT use `app.php` `pluginConfigs` hacks. Memory rule `feedback_edition_switching.md`.

### 6.7 Hash-chained audit log architecture (Phase G G1)

SHA-256 forward chain. Canonical JSON shape: alphabetical key order, UTC ISO 8601 timestamps, first-row sentinel `previousHash = '0' × 64`. `dateCreated` participates in canonicalisation; timezone-normalised via formatting in UTC before hashing. `AuditLogService::canonicalize()` produces bit-identical bytes across PHP versions.

Verifier CLI (`password-policy/audit/verify`) walks the chain. Exit codes: `0` = valid, `1` = first break (with row id), `2` = unreadable / schema drift. Retention-purge-tolerant — partial chains exit `0` with notice.

### 6.8 Element-ified table conventions (Phase G post-review Steps 4–6)

`NotificationLogElement`, `AuditLogElement`, `PolicyElement` all FK their `id` column to `craft_elements.id` CASCADE delete. Element-delete cooperates with retention purge — `dateDeleted` is the new soft-delete boundary; `EVENT_AUDIT_CHAIN_ROTATED` still fires on permanent deletion.

Element queries (`AuditLogQuery`, `NotificationLogQuery`, `PolicyQuery`) inherit the standard `ElementQuery` API. Custom methods layered on top per element.

### 6.9 PII allowlist — fail-closed (Phase G G5)

Per-event-class allowlist registered in `AuditLogService::ALLOWED_DETAILS_BY_EVENT`. Unrecognised keys silently dropped before write. Auditor-inspectable per-event config. Codifies the previously implicit allowlist; documentable as a privacy-by-design control.

### 6.10 HMAC key separation (Phase G post-review Step 2)

Dedicated `auditPiiKey` (not `securityKey`) for PII correlation hashes. Rotating `auditPiiKey` destroys historical correlation without breaking session signing / security tokens. CLI generator at `password-policy/audit/generate-pii-key` outputs 64-character random hex.

### 6.11 Webhook HMAC scheme (Phase G G9)

Signature header `X-PasswordPolicy-Signature: sha256=<hex>` over canonicalised payload. Replay window 5 min. Idempotency UUID in `X-PasswordPolicy-Idempotency` header. Secret rotation flow via `RotateWebhookSecretJob` (queue-backed; allows in-flight deliveries to complete on the old secret).

### 6.12 SIEM forwarder protocol (Phase G G8)

Syslog-over-TLS via `\craft\queue\BaseBatchedJob` (`SiemForwardJob`). RFC 5424 frame. Non-transparent newline framing (RFC 6587 §3.4.1) is the default — interop with Splunk HEC, Datadog Logs, Elastic, Logstash, rsyslog verified during build. UDP cut from scope entirely per 2026-05-06 P2.8 scope confirmation. Octet-count framing parked to `ideas.md` as a half-day post-5.2.0 candidate.

### 6.13 Phase 2 edition realignment (2026-05-15)

Three features moved from Pro-only to **every edition**: password history, four compliance presets (NIST / OWASP / PCI-DSS / CIS), expiry-reminder email dispatch. Strict Enterprise preset stays Pro-only (relies on Pro validators). Per-group named-policy CRUD stays Pro-only. Per-site editable templates + activity log + resend stay Pro-only. Custom Twig template paths stay Enterprise-only.

Rationale: a free password-policy plugin without reuse-prevention, compliance presets, or expiry notifications is too skeletal for the security category. The Pro tier's per-group lever + advanced validators + front-end Twig surface + notification editor remains its differentiator.

---

## 7. Reference: source code inventory

> Skippable unless unsure what already exists. Last refreshed 2026-05-18.

### 7.1 Counts (post-Phase G + Phase 2 edition realignment)

- Services: **21**
- Web controllers: **13** + 1 front-end
- Console controllers: **6**
- Models: **7**
- Records: **10**
- Elements: **3** (NotificationLogElement, AuditLogElement, PolicyElement)
- Element queries: **3**
- Element actions: **4**
- Condition rules: **8**
- Utilities: **4**
- Twig Tags: **8** + BaseTag = 9
- Validators: **7**
- Events: **9**
- Enums: **3**
- Jobs: **7**
- Asset bundles: **2**
- Permissions: **11**

### 7.2 By component

| Type | Names |
|---|---|
| Services | AlertCooldownService, AuditLogService, BlocklistService, ComplianceAggregateService, GuzzleHibpClient, HibpClientInterface, NotificationActivityService, NotificationService, NotificationTemplateService, PasswordHistoryService, PasswordService, PolicyResolverService, PolicyService, RegistrationService, RetentionService, SecurityService, SiemService, StrengthService, UserIndexService, UserStateService, WebhookService (+ ServicesTrait) |
| Web controllers | AuditExportController, BlocklistController, NotificationActivityController, NotificationTemplateController, PolicyController, ReportController, RetentionController, SettingsController, SiemForwarderController, UserPasswordController, UserSecurityController, ValidationController, WebhookEndpointController + front/PasswordChangeController |
| Console controllers | AuditController, BlocklistController, GcController, NotificationController, RetentionController, WebhookController |
| Models | AuditContext, GroupPolicyModel, NotificationTemplateModel, PolicyModel, SettingsModel, SiemForwarderModel, WebhookEndpointModel |
| Records | AuditLogRecord (legacy mapping for element), BlocklistWordRecord, NotificationLogRecord (legacy mapping for element), NotificationTemplateRecord, PasswordHistoryRecord, PolicyGroupRecord, PolicyRecord (legacy mapping for element), SiemForwarderRecord, UserStateRecord, WebhookEndpointRecord |
| Elements | NotificationLogElement, AuditLogElement, PolicyElement |
| Element queries | AuditLogQuery, NotificationLogQuery, PolicyQuery |
| Element actions | ChangeUserPassword (every edition), ForcePasswordReset (Pro), ResendNotification (Pro), SendPasswordResetEmail (every edition) |
| Condition rules | BreachedRecentlyConditionRule (Pro), LastChangeReasonConditionRule, PasswordExpiredConditionRule, PasswordExpiringWithinConditionRule, PasswordNeverChangedConditionRule, PasswordResetRequiredConditionRule, PasswordStatusConditionRule, PolicyDriftConditionRule (Pro + Craft Team+) |
| Utilities | AuditExportUtility (Enterprise), AuditSchemaUtility (Enterprise), ComplianceDashboardUtility (Enterprise), RetentionUtility (Lite) |
| Twig Tags | BaseTag, LoginFormTag, PasswordChangeFormTag, PasswordFieldTag, PasswordResetFormTag, PasswordWidgetTag, RequirementListTag, RequirementsHintTag, StrengthMeterTag |
| Validators | CommonPasswordValidator, ContextualValidator, HibpValidator, MinimumCharacterTypesValidator, PasswordHistoryValidator, RepeatedCharsValidator, SequentialCharsValidator |
| Events | AlertCooldownEvent (Enterprise), AuditChainRotatedEvent (Enterprise), AuditExportCompleteEvent (Enterprise), BreachDetectedEvent (Pro), PasswordChangedEvent (Lite), PasswordValidationEvent (Lite), PolicySaveEvent (Pro), UserRegisteredEvent (Lite), WebhookDeliveryAttemptEvent (Enterprise) |
| Enums | ChangeReason, NotificationStatus, PolicyPreset |
| Jobs | AuditExportJob, PasswordResetJob, RotateWebhookSecretJob, SeedBlocklist, SendPasswordExpiryRemindersJob, SiemForwardJob, WebhookForwardJob |
| Asset bundles | PasswordPolicyAsset (CP), PasswordPolicyClientAsset (front-end consumer) |
| Permissions | `pp:settings`, `pp:force-reset-passwords`, `pp:change-user-passwords`, `pp:blocklist-view` → `pp:blocklist-manage`, `pp:notification-templates-manage`, `pp:notification-log-view`, `pp:audit-view`, `pp:audit-verify`, `pp:audit-export` (Enterprise), `pp:siem-manage` (Enterprise), `pp:webhooks-manage` (Enterprise) |

### 7.3 Settings — all now have UI

Phase G shipped CP UI for every previously-unrendered Enterprise setting. `auditLogRetentionDays`, `enableAuditLog`, `adminAlertEmail`, `adminAlertEvents`, `auditPiiKey` (env-var-driven; CP shows current presence status) — all surface in the **Audit** / **Notifications** / **SIEM** / **Webhooks** subnavs. `enableNewDeviceAlerts`, `deviceRetentionDays` deferred until device tracking lands post-5.2.0 (`ideas.md`).

`apiEnabled` + ApiTokenService surface explicitly deferred to 5.3.

### 7.4 Pest test surface (post-Phase H prep, 2026-05-18)

| Type | Count | Notes |
|---|---|---|
| Test files | **134** | `tests/Unit/`, `tests/Integration/{Validators,Services,Models,Records,Controllers,TwigTags,Migrations,MultiSite,ConditionRules,UserIndex,UserEditTab,Audit,Webhooks,Siem,Notifications,Compliance,Elements,…}/` |
| Tests | **802** passing | 0 skipped (+16 over Phase G close) |
| Assertions | **1924** | (+49 over Phase G close) |
| Duration | ~64s | DDEV-driven Pest run |
| Factories | 6+ | UserFactory, GroupFactory, PolicyFactory, BlocklistFactory, PasswordHistoryFactory, SessionFactory (Phase G added factories for AuditLog, SiemForwarder, WebhookEndpoint, AlertCooldown) |
| Stubs / fakes | 4 | HibpClientFake, WebRequestStub, UserStub, TestGuzzleConfig |
| Base test cases | 3 | TestCase (transaction wrap), MigrationTestCase (DDL teardown), MultiSiteTestCase (site cleanup) |

Phase G + post-G remediation + Phase H prep cumulatively added ~470 tests over Phase D's 513 baseline. The bounded-query contract for `UserIndexService::preloadForUsers()` continues to be pinned by `PreloadBatchingTest`.

Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`. Chains ECS → PHPStan → Pest; first failure stops the chain.

### 7.5 Edge cases not covered by Pest (carry into 5.2.x or 5.3)

1. **Queue worker site context for GC and SeedBlocklist jobs** — `ideas.md`-class follow-up.
2. **Concurrent password changes (race condition in history save)** — Adversarial Test Suite candidate, see `ideas.md`.
3. **GraphQL mutation password changes — confirm plugin events fire** — `ideas.md`-class follow-up; no GraphQL surface tests in scope for 5.2.0.
4. **Browser-driven SR a11y verification (T13.11)** — environment-gated, not code-gated. Captured on the QA pass.
5. **Live SIEM/webhook delivery against real receivers** — environment-gated. QA pass uses fake receivers + Mailpit for the Pest pin; live destinations need staging Splunk HEC / Datadog tokens.
