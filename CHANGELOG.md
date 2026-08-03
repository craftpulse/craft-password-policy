# Release Notes for Password Policy

## Unreleased (5.2.0)

> Pro and Enterprise edition expansion. New editions, per-group named policies, password history, advanced validators, HIBP-on-login, front-end Twig render builders, Pest test suite, hash-chained audit log with independent verifier CLI, syslog and webhook forwarders, compliance dashboard with HTML/CSV reports, native element types for audit + notification + policy records, and a redesigned settings UI.

### Added

#### Editions and policy infrastructure

- Plugin editions: Lite (default), Pro, and Enterprise, gated via project config.
- Per-group named policies (Pro): CRUD manager at **Password Policy → Policies** for assigning override policies to user groups.
- Tri-state rule overrides per policy (Off / Global / On): explicit `Off` is honoured against global, "most-restrictive wins" across multi-group users.
- Four policy presets: NIST 800-63B Rev. 4, OWASP ASVS L1, PCI-DSS v4.0.1, Strict Enterprise, applied as starting templates.
- Tabbed policy edit screen: General / Rules / Lifecycle / Blocklist (Enterprise).
- Divergence indicators: blue left-border on fields differing from the preset, blue dot + "N changes" in the policies index.
- "Restore preset defaults" button: re-apply the selected preset's values to a customised policy.
- "Reset all to global" button: clear every override on the current policy in one click.
- Override warnings: Craft-native `warning:` notices on numeric fields and HIBP fail mode when a policy value differs from global.
- Plugin-managed CP icons for the password policy nav section.
- Conflict notice + edit-screen banner: surfaces when a policy's `minLength` exceeds the global `maxLength`.

#### Native element types

- `PolicyElement` (Pro): `passwordpolicy_policies.id` is now a FK to `craft_elements.id`. Element index with sources, sort options, condition rules. CP edit screen uses native element idiom.
- `NotificationLogElement` (every edition: capture is universal per the audit-capture principle), element index at **Notifications → Activity**, status pills via `Cp::statusLabelHtml`, per-user panel embedded on the Password Security screen.
- `AuditLogElement` (Enterprise: index gated, capture universal), append-only (`canSave()` returns false); element actions: View detail, Export selection (Enterprise + `pp:audit-export`).

#### Password lifecycle (Pro)

- Password history: block reuse of the last N passwords. Configurable count (0 disables, max 24) + retention days.
- Advanced validators: `SequentialCharsValidator` (ASCII runs + keyboard rows), `RepeatedCharsValidator` (3+ repeated characters, Unicode-aware), `ContextualValidator` (rejects passwords containing the user's username, email, name, or site name), `CommonPasswordValidator` (blocklist intersection).
- `complexityMode` setting: `individual` runs each toggle separately; `minimum` requires X-of-4 character types via `minimumCharacterTypes`.
- Expiry reminders: `password-policy/notification/send-expiry-reminders [--user=<id>]` console command. Enqueues `SendPasswordExpiryRemindersJob` (BaseBatchedJob, batchSize=100, ttr=300, canRetry≤5) which recomputes its recipient set per batch for natural retry idempotency. Lite returns `ExitCode::UNSPECIFIED_ERROR` with stderr "Pro edition required."
- `RegistrationService::register(array $params): User`: programmatic helper for consumer registration controllers. Resolves group **handles**, pre-validates the proposed password against the resolved policy, persists the user, assigns groups, optionally sends Craft's activation email, fires `UserRegisteredEvent`. Throws `\InvalidArgumentException` on missing required params, unknown group handles, or validation failures.

#### HIBP integration

- HIBP fail mode setting: `open` (accept on API failure) or `closed` (reject).
- HIBP TLS verification override: plugin-level requests force `verify => true` even when `config/guzzle.php` disables it globally.
- HIBP-on-login (Pro): re-checks every signing-in user's password against the Have I Been Pwned breach database via the same k-anonymity protocol used at password-change time. Detection forces `passwordResetRequired = true`, sends a `breach-detected` notification, fires `BreachDetectedEvent`, writes an Enterprise audit row; the login itself is never blocked. Listens to `User::EVENT_BEFORE_AUTHENTICATE`. 24-hour per-user dedup cache. **Privacy invariant**: never logs the plaintext, full SHA-1, or bucket suffix.
- Site-wide HIBP 429 backoff cache: `pp:hibp-429-backoff` short-circuits every caller (change-time + login) when the API recently rate-limited the site. TTL parsed from `Retry-After`; defaults to 60s.

#### Blocklist (Pro + Enterprise)

- New top-level **Blocklist** subnav (Pro) housing: bundled-list stats with SecLists 10,000-entry common-password citation, "Update Common Passwords" cron-driven seed action, admin-managed editable table for custom blocked words (`forms.editableTableField` with diff-on-save), "Check a word" tool (AJAX, case-insensitive, distinguishes bundled vs custom hits).
- Per-policy custom blocklist (Enterprise): schema's `policyId` column already nullable; admins can scope custom words to specific named policies. Validator merges global + applicable per-policy entries.
- `SeedBlocklist` queue job: seeds the common-password blocklist in the background.

#### Notifications and templates (Pro)

- New top-level **Notifications** subnav (Pro): per-(notification key, siteId) editable email templates with subject + plaintext body Twig sources, click-to-copy token chips, env-var-aware sender overrides, and an AJAX test-send rendering against the current admin.
- Storage table `passwordpolicy_notification_templates`: one row per (`notificationKey`, `siteId`) with a JSON `content` column (Craft 5 elements-sites content shape). FK CASCADE on site delete.
- `Sites::EVENT_AFTER_SAVE_SITE` propagation listener: when a new site is added, copies primary-site notification rows into the new site so admins don't see a missing-template state on first edit. Defensive try/catch never blocks the site save.
- Default notification templates seeded at install (and via dated migrations on upgrade): `expiry-reminder`, `breach-detected`, `new-device-alert`, `admin-security-alert`.
- Notifications **Activity** sibling subnav: captures every dispatch attempt (success AND failure) as a `NotificationLogElement` row with rendered subject + body, error message, recipient email, site, and an admin-initiated **Resend** action that re-renders fresh from the current template. Per-user panel on the Password Security screen surfaces the same activity per recipient.
- Custom Twig template paths (Enterprise): `templatePath` field on each notification template lets admins override the DB-stored body with a site Twig template (`templates/_emails/expiry-reminder.twig`, etc.). Subject stays DB-stored. Whitelabeling + brand-enforcement use case.

#### Audit logging (Enterprise)

- `passwordpolicy_audit_log` table + `AuditLogService`: captures `password_changed`, `password_reset_forced`, `account_locked`, `account_unlocked`, `hibp_breach_detected`, `hibp_check_failed`, `policy_changed`, and audit-system events.
- **Hash-chained rows**: every audit row stores `previousHash` + `rowHash` (SHA-256 of canonical JSON + previousHash). `SELECT ... FOR UPDATE` in the writer prevents concurrent-insert races. Tamper-evident from the row level up.
- Canonical JSON spec: alphabetical key order, UTC ISO 8601 timestamps, JSON_UNESCAPED_SLASHES + JSON_UNESCAPED_UNICODE, null-preserving, no whitespace. `canonicalize()` produces bit-identical bytes; `GENESIS_PREVIOUS_HASH` constant is the public source of truth.
- **Independent verifier CLI**: `php craft password-policy/audit/verify [--from=<date>] [--to=<date>] [--json]` walks the chain row-by-row, recomputes each `rowHash`, exits with `ExitCode::OK` (0) on clean pass, `1` on chain break, `2` on unreadable rows. Designed to be auditor-runnable from a fresh checkout; reads raw `Query` cursors (NOT element queries) so retention-purge-tolerant. JSON output mode for CI integration.
- Field-level before/after diffs on policy changes: `PolicyService::beforeSavePolicy()` captures the diff and emits it as the audit row's `details.diff` JSON. Compliance change-management evidence (SOC 2 CC8.1; ISO 27002:2022 A.5.37; NIS2 Art. 21(2)(g)).
- Per-event PII allowlist: `ALLOWED_DETAILS_BY_EVENT` registry codifies which `details` keys each event type may carry. **Fail-closed**: events not in the registry are dropped with a `Craft::warning()` rather than silently allowing arbitrary keys through.
- Dedicated `auditPiiKey` HMAC secret: `CRAFT_AUDIT_PII_KEY` env var (independent of `securityKey`). `password-policy/audit/generate-pii-key` console command provisions one and writes to `.env`. Rotating the key destroys historical correlation without breaking site session/CSRF/asset signing.
- `AlertCooldownService`: per-(eventClass, cooldownKey) dedup substrate. Generalises the F2 notification-log dedup pattern via a dedicated `passwordpolicy_alert_cooldowns` table with composite indexing.
- **Shared Audit Kit engine**: the hash-chain internals (canonicalisation, the `SELECT ... FOR UPDATE` serialised chain write, the chain verifier walk, the id-prefix-safe retention prune, and the HMAC context capture) now run on the `craftpulse/craft-audit-kit` foundation (a new hard dependency), shared byte-for-byte with the rest of the CraftPulse compliance estate. Zero schema change, zero canonical-payload change, zero `rowHash` change: existing 5.1.x production chains verify identically. `AuditLogService::canonicalize()`, `GENESIS_PREVIOUS_HASH`, `CANONICAL_DATE_FORMAT`, the `verify` / `purge` console UX, and the `CRAFT_AUDIT_PII_KEY` env var are all unchanged. Bit-identity is pinned by a golden-vector regression test.

#### Governance audit events (Audit Kit bus)

- Password Policy now **emits** neutral governance events onto the shared Audit Kit dispatch bus for its own administrative actions: `passwordpolicy.policy_saved`, `passwordpolicy.policy_deleted`, and `passwordpolicy.group_assignment_changed` (one per user-group added to or removed from a policy). Category `permissions`; details are fail-closed scalar allowlists (policy handle/uid, group uid, an `assigned` / `unassigned` verb) with no PII. A recorder on the bus (e.g. a compliance aggregator) captures PP's governance changes through the estate's one typed contract.
- Emission is **additive fan-out**, never a replacement: PP keeps its own hash-chained `policy_changed` row and its Auth Kit `AuthEvent` sink. PP registers its event-type definitions with the kit registry but registers no recorder sink on the bus (one-seam discipline). With no recorder installed, emission is a cheap no-op.

#### Auth Kit audit integration (Warden / Warp)

- `integrations\AuthKitAuditSink`: Password Policy is now an audit **sink** for [Auth Kit](https://github.com/craftpulse/craft-auth-kit)'s neutral audit-event contract. Install Auth Kit with Warden or Warp and every passwordless, SSO, passkey, session-revocation, and SCIM event those plugins emit lands on the hash-chained audit log automatically, flowing to the compliance dashboard, exports, SIEM forwarders, and webhooks with zero extra configuration.
- Seven new event classes captured through the sink: `auth_login` (magic link / OTP / passkey / SSO, with `method` + `provider`), `auth_registration`, `passkey_enrolled`, `passkey_deleted`, `session_revoked` (`scope` = `single` / `others` / `backchannel`: IdP-initiated back-channel logouts land in the tamper-evident chain), `scim_provisioned`, and `scim_deprovisioned` (`trigger` = `scim` / `jit`). All added to the fail-closed `ALLOWED_DETAILS_BY_EVENT` allowlist.
- No hard dependency: Auth Kit is a composer `suggest`, never `require`. The sink registers through `Audit::EVENT_REGISTER_AUDIT_SINKS` via a `::class` reference, so the integration is inert (and free) when Auth Kit is not installed. Unknown neutral event names are ignored silently for forward compatibility.

#### Compliance dashboard (Enterprise)

- `ComplianceDashboardUtility`: registered on Enterprise + `pp:audit-view`. CP utility surfaces five aggregates: totals (by event class, last-30-days), chain health (verifier runs inline with 5-minute cache; surfaces `firstBreakRowId` + checked-row-count), 24-hour alert-cooldown activity, pending SIEM forwards (count + oldest age), retention status (per-table oldest-row age + projected next prune).
- `ReportController`: `actionHtml($report)` + `actionCsv($report)` for `audit-summary`, `alert-activity`, `retention-projection`. Permission gate `pp:audit-view`; edition gate Enterprise defense-in-depth in `beforeAction`. Unknown report keys return 404. CSV uses `Response::FORMAT_RAW`.
- URL rules `password-policy/reports/<report>/{html|csv}`.

#### Forwarders (Enterprise)

- SIEM forwarder: syslog-over-TLS with circuit breaker. `passwordpolicy_siem_forwarders` table; CP edit screen at **Password Policy → Forwarders**; `SiemForwardJob` (BaseBatchedJob) reads unforwarded audit rows via `UnforwardedAuditRowBatcher`. RFC 5424 frame shape with non-transparent newline framing. At-least-once-to-one semantics: a row counts as forwarded the moment ONE endpoint accepts it; downstream SIEMs dedup on `uid`. Documented compatibility via the generic HTTP destination + custom headers: Splunk HEC, Datadog Logs.
- Webhook forwarder: `passwordpolicy_webhook_endpoints` table; CP edit screen at **Password Policy → Webhooks**; HMAC-signed delivery with `X-PasswordPolicy-Signature: sha256=<hex>` header. Signed envelope is `{timestamp}.{eventId}.{body}` to bind signatures to the body and prevent replay across different events. 5-minute replay window via `X-PasswordPolicy-Timestamp`; idempotency UUID via `X-PasswordPolicy-Event-Id`. Per-endpoint watermark via `lastDeliveredRowId` (independent subscribers, NOT at-least-once-to-one).
- `RotateWebhookSecretJob`: operator-triggered secret rotation with a grace window. Old secret retained until reaper job runs; both old and new signatures verify during the window.

#### Audit export (Enterprise)

- Streaming audit-log export: `actionExport` returns the file inline for ≤1,000 rows (synchronous CSV/JSONL); larger requests enqueue `AuditExportJob` (BaseBatchedJob + `AuditExportBatcher`) and surface a one-time download token via the `password-policy:audit-export-ready` system email.
- Filesystem-agnostic: exports write to `@runtime/password-policy/exports/` by default; configurable via `auditExportFilesystem` (any Craft `FsInterface`, S3, FTP, etc.).
- Token-gated download: `password-policy/audit-export/download/<token>` with per-admin binding (cache entry stores `requestedById`; download rejects mismatched users with 403). One-time-use; cache entry deleted on successful serve.
- Permissions: `pp:audit-view` (read), `pp:audit-export` (write), `pp:audit-verify` (verifier CLI).

#### Front-end Twig surface (Pro)

- Fluent render builders on `craft.passwordPolicy.*`: `passwordField()`, `requirementList()`, `strengthMeter()`, `requirementsHint()`, `passwordWidget()` (composite). Form renderers: `loginForm()`, `passwordChangeForm()`, `passwordResetForm()`. Each accepts chained setters OR a config-array constructor; per-element `*Attrs()` setters merge into the rendered markup with empty values omitted.
- Accessibility: live region, `aria-describedby` linking input to requirements list, `aria-invalid` toggled on validation state, `aria-busy` during AJAX, screen-reader announcements for pass/fail transitions, `role="progressbar"` on the strength meter with `aria-valuemin/max/now`. Show/hide toggle with inline SVG eye/eye-slash icon, flipping `aria-label`.
- Data accessors: `requirements({groups: […]})` returns the resolved policy as a flat typed array (Lite returns global; Pro resolves per-group; anonymous group preview supported). `requirementsText()` returns a single-sentence summary. `requirementRules()` returns `[{key, label, met}]` for bespoke checklists.
- Vanilla JS client (`src/web/assets/passwordpolicyclient/password-policy.js`): framework-free, ~5KB unminified, auto-registered by any builder with `liveValidation`, `toggleVisibility`, or `submitGate`. Attaches to `[data-pp-validate]`, debounces 250ms, POSTs to `password-policy/validation/validate`. Consumers need no Vite or build step.
- `Front\PasswordChangeController`: logged-in change. Validates current password via `User::authenticate()`, validates new against the resolved policy, saves through `Craft::$app->elements->saveElement()`. Belt-and-braces session destroy via `PasswordService::destroyOtherSessions()`.

#### Admin user-edit surface

- **Password Security** tab on the user edit screen: surfaces the user's policy status (expired, expiring soon, breached recently, force-reset pending, never changed, ok), last password change date, days until expiry, applied policies, force-reset history, and per-user notification activity. Uses native element-index conventions; status pills via `Cp::statusLabelHtml()`.
- Element actions: `ChangeUserPassword` (single-user; opens an elevated-session modal), `SendPasswordResetEmail` (bulk), `ForcePasswordReset` (bulk).
- Force a password reset on one named user (Pro), whether or not their password has expired, from three surfaces: the `ForcePasswordReset` bulk element action on the Users index, the "Force password reset" item in the user-edit action menu, and the Actions pane on the user-edit **Password Security** screen. Additive to the mass expired-only reset that runs on every edition.
- Added `craftpulse\passwordpolicy\services\RetentionService::forceResetForUser()`: the per-user write, which flags the account, pins a `ChangeReason::AdminForceReset` pending reason, and records a `password_reset_forced` audit event.
- Added `craftpulse\passwordpolicy\services\SecurityService::canManageUserCredentials()`: the peer-admin gate consulted by every admin-on-user credential write, both the direct password change and all three per-user force-reset surfaces. Call it before `craftpulse\passwordpolicy\services\RetentionService::forceResetForUser()`, or before any custom credential write, and reject on `false`.
- User-index columns and condition rules: Last Password Change, Days Until Expiry, Expired, Reset Required, Status (composite seven-state pill), Last Change Reason; Pro adds Breached Recently, Policy Drift, Applied Policies. Sort options + condition rules expose every column to the user index.
- `pp:change-user-passwords` permission: gates `ChangeUserPassword` action + `UserPasswordController` (CP POST, elevated session required). Only an admin can set another admin's password, whoever holds the permission.
- User-state capture: `passwordpolicy_user_state` table records each user's last breach-check time, breached-recently flag, pending change reason. Captured on every edition per the audit-capture principle; Pro/Enterprise expose more of it through the user-index columns.

#### Strength engine

- Server-side strength engine: `bjeavons/zxcvbn-php` (MIT). Analyses passwords against patterns, dictionaries, keyboard sequences, and (when context is supplied) the user's own username/email. Returns a 0-4 score, crack-time estimate, suggestions, optional warning.
- `StrengthService`: registered in `ServicesTrait`. Wraps zxcvbn-php into a stable `{engine, label, score, crackTime, suggestions, warning}` response shape.
- Single engine drives the CP strength indicator AND the front-end Twig render builders via the shared `password-policy/validation/validate` AJAX endpoint.

#### Settings UI

- Settings UI redesigned: sidebar grouped under Policy / Validation / Monitoring / Audit. Higher-edition sections are omitted from the sidebar on lower editions rather than listed and locked.
- Info icon tooltips on every settings page with framework references (NIST 800-63B, PCI-DSS, GDPR, NIS2).
- Configuration page exposes `enableHibpOnLogin`, `useZxcvbnStrength`, `cspNonce`, and the `hibp` / `hibpFailMode` fields. Higher-edition fields are omitted on lower editions.
- Retention page exposes `auditLogRetentionDays`, `notificationLogRetentionDays`, `passwordHistoryExpiryDays`, expiry reminder window. Pro fields are absent on Lite.

#### Permissions

- `pp:manage-settings`: gates the plugin settings screens and the named-policy configuration surfaces (settings sections, `PolicyController`, `PolicyElement` authorization). Estate settings-permission doctrine: the permission gates the screens (a non-admin holding it reaches Settings), never `requireAdmin`; `allowAdminChanges` governs writability only (read-only rendering), never screen access.
- `pp:blocklist-view` / `pp:blocklist-manage` (nested): read access vs write access.
- `pp:notification-templates-manage`: gates the Notifications page + template controllers.
- `pp:notification-log-view`: gates the Activity index + per-user notification panel (separate from templates-manage so log auditors don't need template edit rights).
- `pp:change-user-passwords`: gates `ChangeUserPassword` action + `UserPasswordController`.
- `pp:user-force-reset` (Pro): gates the three per-user force-reset surfaces and the `UserSecurityController::actionForceReset()` POST handler. Separate from `pp:force-reset-passwords`, which stays universal and gates only the mass expired-only reset; holding the mass grant does not open the per-user endpoint.
- `pp:audit-view`: read access to the audit log + compliance dashboard + reports.
- `pp:audit-verify`: runs the verifier CLI.
- `pp:audit-export`: write-side privilege for the audit export utility.
- `pp:siem-manage`, `pp:webhooks-manage`: Enterprise-only.
- Edition-scoped registration: every permission that gates a Pro or Enterprise screen registers only on that edition, so a lower edition's permissions screen never lists a grant that leads nowhere. Existing grants survive a downgrade untouched and take effect again on upgrade.

#### Events

- `PasswordChangedEvent` (Lite, all editions)
- `UserRegisteredEvent` (Lite, fired by `RegistrationService::register()`)
- `BreachDetectedEvent` (Pro, fired by the HIBP-on-login listener)
- `PasswordValidationEvent` (Lite, fired during the validation pipeline)
- `EVENT_BEFORE_SAVE_POLICY` / `EVENT_AFTER_SAVE_POLICY` (Pro extension seam on `PolicyService`)
- `EVENT_AUDIT_CHAIN_ROTATED` (Enterprise capture; payload Enterprise-only)
- `EVENT_POLICY_CHANGED` (every edition capture; Enterprise consumes)
- `EVENT_ALERT_COOLDOWN_FIRED` (every edition capture)
- `EVENT_SIEM_FORWARD_ATTEMPT` (Enterprise)
- `EVENT_WEBHOOK_DELIVERY_ATTEMPT` (Enterprise)
- `EVENT_AUDIT_EXPORT_COMPLETE` (Enterprise)
- Catalog with payload tables + example listener code in `docs/user/reference/events.md`.

#### Test suite

- Pest test suite: 791 tests / 1,888 assertions at release. Integration coverage spans validators, services (Blocklist, PasswordHistory, PolicyResolver, Strength, Hibp via Guzzle MockHandler + `HibpClientFake`), models (`GroupPolicyModel` boolean tri-state, `SettingsModel` legacy alias), controllers (`ValidationController` context hardening, `destroyOtherSessions`, audit-export controller binding, notification-template guards), Twig tags (`PasswordWidgetTag` composite null-gating), migrations (5.1.1 → 5.2.0 upgrade replay covering T1.2 + TX.2), multi-site (notification template propagation + FK CASCADE soft-delete contract covering T9.7).
- Test infrastructure: `tests/bootstrap.php` (`$_SERVER` pin block), `MigrationTestCase` + `MultiSiteTestCase` non-transactional bases (DDL + project-config writes auto-commit; transaction wrappers are inadequate), factories (User, Group, Policy, Blocklist, PasswordHistory, Session), stubs (`HibpClientFake`, `WebRequestStub`, `UserStub`, `TestGuzzleConfig`).
- Run via `ddev composer test`: chains ECS → PHPStan (level configured per `phpstan.neon`) → Pest.

#### Console commands

- `password-policy/notification/send-expiry-reminders [--user=<id>]`: queues `SendPasswordExpiryRemindersJob` (Pro+).
- `password-policy/blocklist/seed-common`: seeds the bundled common-password list (10,000 entries from SecLists).
- `password-policy/audit/verify [--from=<date>] [--to=<date>] [--json]`: independent chain verifier (Enterprise + `pp:audit-verify`).
- `password-policy/audit/generate-pii-key`: generates `CRAFT_AUDIT_PII_KEY` + writes to `.env`.
- `password-policy/gc/run`: retention/expiry housekeeping for all retention-managed tables. Recommended production setup as a daily cron.
- `password-policy/retention/force-reset-passwords`: forces a reset on every account already past the expiry window. Takes no target and runs on every edition. `--verbose` reports each account, `--queue` pushes the work to a queue job.

### Changed

- **Edition gating hides, it never badges.** Higher-edition functionality no longer renders at all on lower editions: no disabled fields, no locked sidebar rows, no upsell callouts, and no copy naming a surface the edition can't reach. Three layers carry it. (1) CP nav entries, settings sidebar sections, utilities, element-index columns, condition-rule options, and the per-user notifications panel are omitted below their edition. (2) Permissions for higher-edition surfaces register only on those editions. (3) A direct hit on a higher-edition CP URL now answers **404** (`NotFoundHttpException`) instead of 403, via the shared `RequiresEditionTrait` on `SettingsController`, `PolicyController`, `BlocklistController`, `InactiveAccountController`, `NotificationTemplateController`, `NotificationActivityController`, `GroupAlertController`, `ReportController`, `AuditExportController`, `SiemForwarderController`, `WebhookEndpointController`, and `ApiTokenController`: a 403 would confirm a screen the hidden nav withholds. The read-only REST API returns its existing uniform JSON 404 below Enterprise, byte-identical to the `apiEnabled = false` response. Service, Twig-variable, queue-job, and console gates are unchanged (`EditionRequiredException`, graceful skip, non-zero exit).
- **Force password reset now splits into a universal mass path and an additive Pro per-user path.** The mass path is unchanged from 5.1.2 and runs on every edition: the **Password Retention** utility's "Force Reset Passwords" action and the `password-policy/retention/force-reset-passwords` console command both flag every account already past the configured expiry window, still gated by `pp:force-reset-passwords`, which registers on every edition. The per-user path is Pro and targets named accounts whether or not their passwords have expired: the `ForcePasswordReset` bulk element action, the "Force password reset" user-edit action-menu item, and the Actions pane on the user-edit **Password Security** screen. Those three moved onto a new `pp:user-force-reset` permission that registers on Pro+ only, and `UserSecurityController::actionForceReset()` gates on edition before permission so a Lite POST answers **404** rather than 403. Below Pro the pane is absent rather than disabled or badged (driven by a `showForceReset` flag that defaults closed, so a missing variable fails safe); the Password Security screen itself stays universal and just omits the pane.
- The per-user force reset pins `ChangeReason::AdminForceReset` where the mass path pins `ChangeReason::ExpiryForced`, so the history row records whether an operator named the account or a retention sweep reached it. Both write a `password_reset_forced` audit event.
- The whole `BlocklistController` is now Pro-gated rather than only its index and save actions. The word-lookup and common-list refresh endpoints only exist on the Pro editor page; Lite operators seed the bundled list with the `password-policy/blocklist/update` console command, which runs on every edition.
- Settings screens now gate on the `pp:manage-settings` permission instead of `requireAdmin`, aligning Password Policy with the estate settings-permission doctrine. `SettingsController` and `PolicyController` `beforeAction()` gates switched from `requireAdmin` to `requirePermission(pp:manage-settings)`, so a non-admin holding the permission can reach and manage settings; `allowAdminChanges` now governs writability only (the read views already render read-only with disabled fields and no save button when it is off). The permission handle was renamed from `pp:settings` to `pp:manage-settings` and is declared once as `PasswordPolicy::PERMISSION_MANAGE_SETTINGS`, referenced from the registration, the CP nav gating, both controllers, the settings and policy CP templates, and the policy element authorization.
- **Permission handle renamed:** `pp:settings` (5.1.x) is now `pp:manage-settings`. Permission handles are kebab-case across the CraftPulse plugin estate, so both halves of the handle are lowercase kebab. `m260729_*_KebabCasePermissions` carries existing grants over automatically: user grants, user group grants, and the `users.groups.<uid>.permissions` project config lists all move to the new name, and the old permission row is removed. No manual re-granting is needed, and integrators only need to update their own `currentUser.can('pp:settings')` checks and any permission lists they manage outside Craft. The intermediate `pp:manageSettings` form used during 5.2.0 development is carried over by the same migration and never shipped in a release.
- CP password strength indicator now consumes the same AJAX `password-policy/validation/validate` endpoint as the front-end builders: single strength engine across CP and consumer surfaces. Selector generalised from `#newPassword` to `input[type="password"][autocomplete="new-password"]:not([data-pp-no-strength])`; attaches on installer + set-password screens too. Dropped `@zxcvbn-ts/core` + `@zxcvbn-ts/language-common` + `@zxcvbn-ts/language-en` from the buildchain in favour of the server-side `bjeavons/zxcvbn-php` engine, JS bundle dropped from ~1.65 MB to ~2.2 KB.
- Settings UI redesigned: sidebar grouped under Policy / Validation / Monitoring.
- `pwned` setting renamed to `hibp` (project config + DB): `m260429_224908_UpgradeTo520Schema` migration handles the rename. `SettingsModel` accepts the legacy `pwned` / `pwnedFailMode` keys from `config/password-policy.php` and aliases them to `hibp` / `hibpFailMode` with a deprecation warning logged at `WARNING`.
- Subnav lists Policies before Settings (when per-group policies enabled).
- `SequentialCharsValidator` detects ASCII sequences (e.g. `pqr`, `xyz`) in addition to keyboard rows. Unicode-aware character classes in `MinimumCharacterTypesValidator` + `RepeatedCharsValidator`.
- `lastPasswordChangeDate` queried directly to bypass `UserQuery::beforePrepare()` not selecting it.
- Sensitive keys (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`) automatically stripped from plugin log entries via `PasswordPolicy::log()`.
- Common password blocklist stored separately from custom dictionary (`source = 'common'` vs `'custom'`): prevents flooding the admin UI. Source-aware validator messages distinguish "too common, choose a more unique password" from "blocked, choose a different one."
- `craft.passwordPolicy` (camelCase) variable handle registered alongside the existing `craft.passwordpolicy` (lowercase) handle. Both work permanently; new code should prefer the camelCase form.
- NIST preset bumped to 15-char `minLength` per Rev 4 (finalised 31 July 2025). Preset also enables `checkCommonPasswords` to satisfy §3.1.1.2 SHALL ("compare against a blocklist of commonly used, expected, or compromised passwords"). §3.2.2 rate-limiting (≤100 consecutive failed attempts) is delegated to Craft core (`maxInvalidLogins`).
- User-index renderers use `Cp::statusLabelHtml()` + `Color` enum; expiry-dependent columns + sort options gated on `expiryAmount` being configured.
- `UsersController::EVENT_DEFINE_EDIT_SCREENS` registration replaces the prior sidebar-pointer workaround for the Password Security tab.
- `Element::EVENT_DEFINE_ACTION_MENU_ITEMS` listener appends Force Reset / Send Reset Email / Change Password… to the per-user edit screen "…" menu.
- Force-reset action moved from `RetentionController::actionForceReset` to `UserSecurityController::actionForceReset`. URL rule `password-policy/user-security/force-reset` (was `password-policy/retention/force-reset`). Semantic naming: force-reset is user-security, not retention.
- `_dispatchMailerKey()` path retired in `NotificationService`: `new-device-alert` and `admin-security-alert` keys moved to the editable-templates path so admins can edit them like `expiry-reminder` and `breach-detected`.
- HIBP-on-login dedup cache key uses `userId` only (was `(userId, sha1Prefix)`). Prefix-in-key reconstructed the linkability property k-anonymity is designed to prevent.

### Fixed

- `getIsLite()` no longer hardcoded to `return true`: uses `is(self::EDITION_LITE)`.
- Validation order: content rules run before HIBP/history checks (avoids unnecessary API calls on weak passwords).
- Common password blocklist auto-seeds via queue when the toggle is enabled with an empty blocklist (previously failed silently).
- `expiryPeriod` no longer persisted on policy settings without an `expiryAmount`.
- `craft.passwordpolicy.passwordWidget()` no longer fatals when called without `submitGate`: composite tag gates the optional value before forwarding to the strict-typed child setter.
- Front-end client JS bundle now auto-registers when **any** interactivity flag is on (`liveValidation`, `toggleVisibility`, or `submitGate`): builders with `toggleVisibility: true, liveValidation: false` previously shipped a non-functional show/hide eye button.
- Strength meter now respects `blocklistHit`: a blocklisted word reads as "weak" / score 0.
- HIBP-on-login dedup cache: ambiguity between Yii's `false` cache miss and a `false`-valued hit resolved by string-encoding the cached state (`'breached'`/`'clean'`).
- Hardcoded `admin` cpTrigger removed from JS fallback URLs: both front-end consumer asset and rebuilt CP strength bundle now fall back to Craft 5's native `/actions/...` route, which works regardless of installed `cpTrigger`.
- `BaseTag::__toString()` docblock corrected: Twig auto-escapes the `__toString()` return because PHP's contract requires a plain `string` (not `\Twig\Markup`). Always use `{{ tag.render() }}` from Twig templates; `__toString()` is for PHP-context concatenation only.
- `PasswordResetFormTag` adds an `id()` setter alias matching Craft's reset-email URL `?id=` param name (the legacy `userUid()` setter is preserved for backward compatibility).
- `PasswordExpiredConditionRule::matchElement()` hydrates `lastPasswordChangeDate` directly: previously matched against null since `UserQuery` doesn't select the column.
- `passwordResetRequired` column pre-loaded in the user-edit short-circuit so the "Password reset has been requested" banner renders and the Force Password Reset button doesn't show when reset is already pending.
- Notification dedup gate filters on `status = 'sent'`: failed-then-retried no longer suppresses the next attempt.
- NIS2 transposition status accuracy throughout docs (May 2026): 21/27 EU Member States transposed; Hungary first audit deadline 30 June 2026.
- `ContextualValidator` now checks the primary site's domain against passwords even when its host has no TLD (e.g. `localhost`, an internal hostname): the stem extraction previously required at least two dot-separated segments and silently skipped single-label hosts entirely.
- `NotificationActivityService::recentFailureCount()` now computes its window threshold in UTC: it previously used the ambient process timezone (`system.timeZone`) against the naive-UTC `sentAt` column, understating or overstating the window by the full offset on any non-UTC install.
- `AuditLogService::logEvent()` no longer silently drops an audit event when the Enterprise chain write fails. A failed inline write is now escalated to an error-level log carrying the full event payload and handed to the new `WriteAuditChainEntryJob`, which retries with a jittered backoff up to a bounded number of attempts before giving up loudly. Under concurrent load, the currently-installed Audit Kit tag has no bounded retry of its own at the write layer, so a chain write that lost the tail-row lock wait previously reported success while the event vanished.
- `WriteAuditChainEntryJob`'s failure log now distinguishes Audit Kit's own exhausted-retry-budget exception from any other chain-write failure, now that the dependency constraint resolves the kit release that ships it. Internal reliability improvement; the requeue-with-backoff behavior is unchanged.
- `UserIndexService::_toDateTime()`, `NotificationService::_estimateDaysUntilExpiry()`, and `BreachedRecentlyConditionRule::matchElement()` now parse `users.lastPasswordChangeDate` / `lastBreachDetectedAt` as explicit UTC. All three previously parsed the naive-UTC DB string in the ambient process timezone (`system.timeZone`), shifting the Users-index security state (breached-recent, expired/expiring, `daysUntilExpiry`, card timestamps), an expiry-reminder resend's recomputed day count, and the "breached recently" condition rule's match by the full UTC offset on any non-UTC install.
- `PolicyElement::_syncGroupIds()` and `NotificationTemplateService::propagateToSite()` now route their `dateCreated` / `dateUpdated` writes through `Db::prepareDateForDb()` instead of writing a bare `(new \DateTime())->format(...)` (the ambient process wall clock) directly into the UTC-convention columns via `createCommand()`. Both previously stored a timestamp offset by the full UTC offset on any non-UTC install.

### Security

- A non-admin can no longer force a password reset on an admin. `pp:user-force-reset` is grantable to non-admins, and forcing a credential change on an administrator's account is an escalation primitive, so the guard sits below the permission: the Password Security pane renders no button, the `ForcePasswordReset` bulk element action refuses the whole run rather than partially applying it and silently skipping the admin, and `UserSecurityController::actionForceReset()` answers 403. An admin acting on another admin is allowed, and the mass path still never touches admin accounts on any edition.
- `NotificationTemplateController::actionSave` and `actionTestSend` now enforce `allowAdminChanges` via `ForbiddenHttpException`. A crafted POST cannot mutate notification templates on production environments where admin changes are disabled.
- `NotificationTemplateController::actionTestSend` no longer returns raw `$e->getMessage()` in the JSON response. Mailer transport details (SMTP host, auth failures, internal paths from Twig render errors) stay in the plugin log; the client gets a static breadcrumb.
- `NotificationTemplateController` exception messages no longer embed attacker-controlled POST values. `NotFoundHttpException` thrown with the default "Page not found." message; the specific value is logged via `Craft::warning()` for operational visibility.
- `WebhookEndpointController::actionRotateSecret` no longer leaks the underlying exception from `WebhookService::rotateSecret()`. Errors logged via `Craft::error()`; client gets a static "couldn't rotate secret" message.
- HIBP-on-login dedup cache key dropped the `sha1Prefix` component (now `userId` only): eliminates the `(userId, prefix)` ledger that an operator with Redis/Memcache access could enumerate.
- `PasswordHistoryService::isPasswordReused()` routes password comparison through `Craft::$app->getSecurity()->validatePassword()` rather than `password_verify()` direct: consistent with the active-password check across site-level pepper customisation.
- `AuditExportController::actionDownload` binds the download token to the requesting admin. Cache entries that don't match the requesting user's ID return 403 `ForbiddenHttpException`; legacy entries without `requestedById` fail closed.
- `AuditExportController::_streamSynchronousResponse` adds a `LIMIT 1000` clause on the sync-path query: closes the TOCTOU race between the count check and the row fetch.
- `BreachDetectedEvent::$sha1Prefix` documents the "do not persist alongside `$user->id`" warning explicitly. The k-anonymous prefix is safe in isolation; pairing it with the user ID recreates linkability.
- Translator-injectable `|raw` patterns removed from `_policies/_edit.twig` and `_utilities/audit-export.twig`. `<strong>` and `<code>` tags now constructed via `tag()` so a malicious translation source can't inject script content.
- `_policies/_edit.twig` radiogroup widget gains full WAI-ARIA keyboard navigation (arrow keys + Home/End).
- Bare color-only status indicators on the Password Security tab now carry `aria-hidden="true"` since adjacent text already describes the state (WCAG SC 1.4.1).
- HIBP TLS verification: plugin-level requests force `verify => true` even when `config/guzzle.php` disables it globally.
- Project-config writes wrapped in `muteEvents = true` try/finally to prevent re-entrant subscriber loops during plugin-managed key renames.
- Bcrypt seed loops in migrations toggle `enableLogging` + `enableProfiling` off, restored in `finally`: prevents Yii's debug logger from capturing hashes at SQL bind time.
- `SettingsController::actionSave` unconditionally `unset()`s Pro/Enterprise keys when running on a sub-edition. Defense-in-depth even though the UI hides the gated fields.
- `NotificationTemplateController::actionSave` + `actionTestSend` strip `templatePath` on non-Enterprise editions. `Craft::warning()` logged when a non-null value is stripped: operators can spot crafted POSTs.
- `ValidationController::actionValidate` no longer trusts attacker-controlled `username` / `email` POST params for zxcvbn user-input dictionary on anonymous requests. Truncates context strings to 254 chars defensively.

### Removed

- `BlocklistUtility` (Utilities → Password Blocklist): its stats and "Update Common" affordances absorbed into the new Blocklist subnav page, the editable custom-word editor lives there too. Single mental model instead of split surfaces.

## 5.1.2 - 2026-05-02

> Maintenance release on the `5.1.x` branch. Three backports from `5.x` security work — does not include 5.2.0 Pro / Enterprise expansion. Independent of the `5.x` linear release sequence.

### Changed

- Bumped HIBP fail-open log level from `ERROR` to `WARNING`. A transient HIBP outage shouldn't trigger ERROR-level alerts in operator monitoring.
- `PasswordPolicy::log()` strips sensitive keys (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`) from logged params as defense-in-depth for third-party listener authors.

### Fixed

- Fixed HIBP requests not enforcing TLS verification when a site-level `config/guzzle.php` had `verify => false`. The plugin now always verifies TLS on the Pwned Passwords API call regardless of the site's Guzzle defaults.

## 5.1.1 - 2026-05-02
### Changed
- Symbols regex now accepts any non-alphanumeric character (hyphens, underscores, etc.) instead of a limited set [#46](https://github.com/craftpulse/craft-password-policy/issues/46)
- Console `force-reset-passwords` command now runs synchronously by default; use `--queue` to push to the queue instead
- Password expiry query now filters at the database level instead of hydrating all users into memory, significantly improving performance on large user bases
- Replaced `switch` with `match` expression in `PasswordResetHelper`
- Applied coding conventions: section headers, `@author` on methods, `@throws` annotations, underscore-prefixed private members

### Fixed
- Fixed a critical security issue where `RetentionController` had CSRF disabled and allowed anonymous access, enabling unauthenticated mass password resets
- Fixed `RetentionController::afterAction()` blocking web requests by synchronously draining the entire queue
- Fixed admin account exclusion being hardcoded to user ID 1 instead of using the `admin` property
- Fixed `getCpNavItem()` null dereference when no user is authenticated
- Fixed static `$settings` property never being populated
- Fixed `SettingsController::actionSave()` running permission checks before `requirePostRequest()`
- Fixed `SettingsModel::defineRules()` not calling `parent::defineRules()`
- Fixed console `force-reset-passwords` returning `ExitCode::OK` when retention features are disabled
- Fixed double `Craft::t()` nesting in `UserRules` that broke non-English translations
- Fixed `SecurityService` class docblock saying "RetentionService"
- Removed dead `$users` property from `PasswordResetJob`
- Removed dead `$vacancyId` parameter from `RetentionController::getFailureResponse()`
- Removed no-op `EVENT_AFTER_SAVE_PLUGIN_SETTINGS` handler
- Replaced redundant ternary with `isNotEmpty()` in `PasswordService::pwned()`
- Fixed `PasswordPolicyAsset` using property access instead of getter for view
- Fixed `$queue` property type from `mixed|object|null` to `?object`

## 5.1.0 - 2025-10-28
### Added
- Added optional CSP (Content Security Policy) nonce support for the password indicator script [#39](https://github.com/craftpulse/craft-password-policy/issues/39)
- Added `SecurityService` to generate and manage CSP nonces per request
- Added `cspNonce` configuration option to enable CSP nonce generation

### Changed
- Made sure that the rules thrown by Password Policy all show at once, rather than one by one.

### Fixed
- Fixed an issue where the native Craft errors would still display when password policy was active [#40](https://github.com/craftpulse/craft-password-policy/issues/40)
- Fixed an issue where the retention feature never actually got processed [#41](https://github.com/craftpulse/craft-password-policy/issues/41)

## 5.0.3 - 2025-01-07
### Changed
- Added services to a service trait

### Fixed
- Fixed a bug that could occur if the max length wasn't set, passwords always said "could not contain more than 0 characters".
- Removed the "playground" from the settings to test the strength indicator, this was only meant for development.
- Fixed an issue where the pwned option would always return that the password was compromised.
- Fixed the issue where the assets would throw an error on the front-end, not finding the manifest path. (Thanks to Andrew Welch) [#34](https://github.com/craftpulse/craft-password-policy/issues/34)

## 5.0.2.1 - 2024-12-19
### Fixed
- Fixed `Failed to instantiate component or class` on the assetbundle [Thanks niektenhoopen](https://github.com/craftpulse/craft-password-policy/pull/33)

## 5.0.2 - 2024-12-16
### Fixed
- Fixed native type class constant as those are only allowed from PHP8.3+

## 5.0.1.1 - 2024-12-16
### Fixed
- More ECS fixes after PHPStan fixes

## 5.0.1 - 2024-12-16
### Fixed
- ECS Style fixes
- Fixed PHP Stan Errors

## 5.0.0 - 2024-12-15
### Added
- Added a "Have I been pwned" validator [#29](https://github.com/craftpulse/craft-password-policy/issues/29)
- Added "Have I been pwned" through k-anonymity
- Password Retention feature to determine on which time interval passwords should expire
- Added the `craft password-policy/retention/force-reset-passwords` CLI command
- Added the "Force Reset Passwords" Retention Utility

### Changed
- Refactored the password strength indicator, now using vanilla JS and TailwindCSS
- Refactored all the validation rules
