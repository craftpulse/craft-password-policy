# Release Notes for Password Policy

## Unreleased

> [!WARNING]
> Password Policy now requires Craft 5.9.15 or later. Run `composer update craftcms/cms` before updating the plugin.

> [!WARNING]
> The `pp:settings` permission is now `pp:manage-settings`. Run `php craft up` to carry existing grants over, then update any `can('pp:settings')` checks in your own templates and code.

> [!WARNING]
> The settings screens now gate on `pp:manage-settings` rather than requiring an admin account, so review who holds that permission before you update.

> [!WARNING]
> The `pwned` and `pwnedFailMode` settings are renamed to `hibp` and `hibpFailMode` in project config. Run `php craft up`, then commit the rewritten `project.yaml` before deploying to another environment.

> [!WARNING]
> The control panel strength indicator now scores passwords server-side over `password-policy/validation/validate` instead of in the browser, so the indicator stops updating on installs where that action route is unreachable.

### Policy Enforcement
- Added five policy presets: NIST 800-63B Revision 4, OWASP ASVS L1, PCI-DSS v4.0.1, CIS Controls v8, and Strict Enterprise.
- Added per-group named policies, with a "Policies" screen for assigning an override policy to one or more user groups (Pro).
- Added tri-state rule overrides per policy, so an explicit "Off" is honoured against the global setting and the most restrictive value wins for a user in several groups (Pro).
- Added a tabbed policy edit screen split into General, Rules, Lifecycle, and Blocklist (Pro).
- Added divergence indicators to the policy edit screen and the policies index, marking every field that differs from the selected preset (Pro).
- Added "Restore preset defaults" and "Reset all to global" buttons to the policy edit screen (Pro).
- Added a conflict notice on the policies index and edit screen when a policy's `minLength` exceeds the global `maxLength` (Pro).
- Added password history, which blocks reuse of up to the last 24 passwords and prunes entries after `passwordHistoryExpiryDays` (Pro).
- Added the `minChangeIntervalHours` setting, which refuses a self-service password change within that many hours of the last change so password history cannot be cycled out, and exempts admin-forced, first-login, expiry-forced, and breach-forced changes (Pro).
- Added the `craftpulse\passwordpolicy\validators\SequentialCharsValidator`, `craftpulse\passwordpolicy\validators\RepeatedCharsValidator`, `craftpulse\passwordpolicy\validators\ContextualValidator`, and `craftpulse\passwordpolicy\validators\CommonPasswordValidator` validators (Pro).
- Added the `complexityMode` setting, where `individual` runs each character-type toggle separately and `minimum` requires `minimumCharacterTypes` of the four types.
- Added a server-side strength engine built on `bjeavons/zxcvbn-php`, returning a 0 to 4 score, a crack-time estimate, and suggestions.
- Added the `hibpFailMode` setting, which chooses whether a password is accepted or refused when the Have I Been Pwned API cannot be reached.
- Added breach checking at login, which forces a password reset and sends a notification when a signing-in user's password is found in the Have I Been Pwned database, without blocking the login itself (Pro).
- Added the `enableHibpOnLogin` setting, which turns breach checking at login on (Pro).
- Added a site-wide backoff that short-circuits every Have I Been Pwned caller for the length of the API's `Retry-After` window after it rate-limits the site.
- Added a "Blocklist" screen carrying the bundled 10,000-entry common-password list from SecLists, an editable table of custom blocked words, and a word-lookup tool (Pro).
- Added per-policy custom blocked words, so a word can be scoped to named policies instead of the whole install (Enterprise).
- Common passwords are now stored separately from custom blocked words, so the bundled list no longer floods the custom-word editor and the two produce different validation messages.
- The NIST preset now sets a 15 character minimum and enables common-password checking, per Revision 4 as finalised on 31 July 2025.
- `craftpulse\passwordpolicy\validators\SequentialCharsValidator` now detects ASCII runs such as `pqr` in addition to keyboard rows.
- `craftpulse\passwordpolicy\validators\MinimumCharacterTypesValidator` and `craftpulse\passwordpolicy\validators\RepeatedCharsValidator` now use Unicode-aware character classes.

### User Management
- Added a "Password Security" screen to user edit pages, showing policy status, last change date, days until expiry, applied policies, force-reset history, and notification activity.
- Added the `ChangeUserPassword`, `SendPasswordResetEmail`, and `ForcePasswordReset` element actions to the Users index.
- Added per-user force password reset from the Users index, the user-edit action menu, and the Password Security screen, which targets a named account whether or not its password has expired (Pro).
- Added Last Password Change, Days Until Expiry, Expired, Reset Required, Status, and Last Change Reason columns, sort options, and condition rules to the Users index.
- Added Breached Recently, Policy Drift, and Applied Policies columns and condition rules to the Users index (Pro).
- Added login device tracking on every edition, which records a fingerprint of each sign-in's user agent and masked IP so an unrecognised device can be detected without storing the raw user agent or IP.
- Added a new-device alert email, sent once per cooldown window when a user signs in from a device that has not been seen before (Enterprise).
- Added dormant-account detection, which flags active accounts whose last login predates `inactiveThresholdDays` and then reports, emails, or suspends them according to `inactiveAction` (Pro).
- Added an "Inactive accounts" screen listing the accounts the dormant-account scan would flag, with last activity and days inactive (Pro).
- Added a `passwordpolicy_user_state` table recording each user's last breach-check time, breached-recently flag, and pending change reason, on every edition.
- Added `craftpulse\passwordpolicy\services\RegistrationService::register()`, which resolves group handles, validates the proposed password against the resolved policy, saves the user, assigns groups, and optionally sends Craft's activation email.
- Added `craftpulse\passwordpolicy\services\RetentionService::forceResetForUser()`.
- Added `craftpulse\passwordpolicy\services\SecurityService::canManageUserCredentials()`, the peer-admin gate every admin-on-user credential write consults.
- Added the `pp:change-user-passwords`, `pp:user-force-reset`, and `pp:inactive-view` permissions.
- Renamed the `pp:settings` permission to `pp:manage-settings`, carrying existing user grants, user group grants, and project config permission lists over automatically.
- Force password reset now runs on two paths, where the mass sweep over already-expired accounts stays on `pp:force-reset-passwords` and every edition, and the new per-user reset sits on `pp:user-force-reset` and Pro.
- The per-user force reset records `craftpulse\passwordpolicy\enums\ChangeReason::AdminForceReset` where the mass sweep records `craftpulse\passwordpolicy\enums\ChangeReason::ExpiryForced`, so the history row says whether an operator named the account.
- A non-admin can no longer set an admin's password or force a password reset on an admin account, whatever permissions they hold.

### Notifications
- Added a "Notifications" screen with an editable email template per notification key and site, each carrying a subject, a plaintext Twig body, copyable token chips, sender overrides, and a test send (Pro).
- Added the `expiry-reminder`, `breach-detected`, `new-device-alert`, `admin-security-alert`, and `inactive-account` notification templates, seeded at install and on upgrade.
- Added an "Activity" screen recording every dispatch attempt, successful or failed, with the rendered subject and body, the recipient, the site, any error message, and a Resend action (Pro).
- Added a "Group alerts" screen, which routes a copy of a breach or new-device alert to a security contact designated per user group, resolved from the affected user's actual group membership rather than a global setting (Pro).
- Added the `password-policy/notification/send-expiry-reminders` console command, which queues a batched job emailing every user whose password is about to expire (Pro).
- Added a custom Twig template path per notification template, so the stored body can be overridden by a site template while the subject stays in the database (Enterprise).
- Added `craftpulse\passwordpolicy\services\AlertCooldownService`, which throttles repeat alerts per event and key so a burst routes one message per window instead of one per affected user.
- Added the `passwordpolicy_notification_templates` and `passwordpolicy_alert_cooldowns` tables.
- Added the `pp:notification-templates-manage` and `pp:notification-log-view` permissions.
- Notification templates for a newly added site are now copied from the primary site, so a fresh site does not open on a missing-template state.
- The `new-device-alert` and `admin-security-alert` messages are now editable templates rather than fixed mailer keys.

### Audit Logging
- Added a `passwordpolicy_audit_log` table capturing password changes, forced resets, account locks and unlocks, breach detections, breach-check failures, policy changes, and audit-system events (Enterprise).
- Added hash chaining to every audit row, which stores a `previousHash` and a `rowHash` over canonical JSON so removing or altering a row is detectable (Enterprise).
- Added the `password-policy/audit/verify` console command, an independent chain verifier that recomputes every row hash and exits non-zero on a break (Enterprise).
- Added the `--from` and `--to` options to `password-policy/audit/verify`, which bound the walk to a range of audit log row ids (Enterprise).
- Added the `password-policy/audit/purge` and `password-policy/audit/export` console commands (Enterprise).
- Added field-level before and after diffs to policy-change audit rows (Enterprise).
- Added a per-event allowlist for audit row details, which drops any event or detail key that is not registered rather than storing arbitrary data (Enterprise).
- Added the `auditPiiKey` setting and the `password-policy/audit/generate-pii-key` console command, so audit user identifiers are hashed under a secret that can be rotated without touching `securityKey` (Enterprise).
- Added optional IP geolocation on audit rows and new-device alerts, off by default behind the `geoIpEnabled` setting, which resolves the request IP to a country code and never stores the IP itself (Enterprise).
- Password Policy now requires `geoip2/geoip2` and ships the DB-IP IP-to-Country Lite database it reads as an 8 MB file inside the plugin, so no operator download or PECL extension is needed.
- The bundled geolocation database is licensed under CC BY 4.0, so an operator who turns `geoIpEnabled` on must keep the "IP Geolocation by DB-IP (https://db-ip.com)" attribution visible wherever the geolocation data is surfaced, and should refresh the database periodically to keep it accurate.
- Added a compliance dashboard utility surfacing event totals, chain health, alert-cooldown activity, pending SIEM forwards, and retention status (Enterprise).
- Added HTML and CSV reports at `password-policy/reports/<report>/html` and `password-policy/reports/<report>/csv` for `audit-summary`, `alert-activity`, and `retention-projection` (Enterprise).
- Added an audit schema utility and the `password-policy/audit/schema` command, which publish the per-event detail allowlist an auditor needs to read the log (Enterprise).
- Added a "SIEM forwarders" screen and syslog-over-TLS forwarding of audit rows, with a circuit breaker and RFC 5424 framing (Enterprise).
- Added the `password-policy/siem/run` console command, which enqueues the batched job that forwards pending audit rows to every active SIEM forwarder and needs a cron entry to forward on a schedule (Enterprise).
- Added a "Webhooks" screen and HMAC-signed webhook delivery of audit rows, which sends a per-endpoint watermark, a signed `X-PasswordPolicy-Timestamp` for consumer-side replay rejection, and an `X-PasswordPolicy-Event-Id` for idempotency (Enterprise).
- Added webhook secret rotation with a grace window during which both the old and the new signature verify (Enterprise).
- Added the `password-policy/webhook/create`, `password-policy/webhook/list`, and `password-policy/webhook/rotate-secret` console commands (Enterprise).
- Added the `password-policy/webhook/run` console command, which enqueues the batched job that delivers pending audit rows to every active webhook endpoint and needs a cron entry to deliver on a schedule (Enterprise).
- Added a sweep warning to the SIEM forwarders index and the webhooks index, which appears when an audit row has been waiting more than two hours for a first delivery attempt and names the console command that has to be scheduled, so a forward sweep that was never added to cron stops failing silently (Enterprise).
- Added an HTTP destination type to SIEM forwarders, which POSTs each audit row's canonical JSON to an HTTPS collector with an optional bearer or basic credential and any custom request headers the platform needs (Enterprise).
- Added per-forwarder syslog message framing, defaulting to the octet counting RFC 5425 requires of a receiver on port 6514, with newline delimiting available for a receiver that expects line-delimited input (Enterprise).
- A SIEM forwarder's HTTP credential is encrypted at rest, is never rendered back into the edit form, and never appears in a save response (Enterprise).
- The HTTP destination refuses a plaintext URL, re-checks the scheme after resolving an environment variable, never follows a redirect, and treats anything other than a 2xx as a failure (Enterprise).
- Switching a forwarder from the HTTP destination to syslog now clears its URL, authentication type, credential, and custom headers in the same save (Enterprise).
- A forwarder carrying a protocol neither transport handles now records a failure instead of being sent over the syslog transport regardless (Enterprise).
- Added audit log export, returned inline for up to 1,000 rows and queued behind a one-time download link beyond that, writing to any Craft filesystem named by `auditExportFilesystem` (Enterprise).
- Added the `passwordpolicy_siem_forwarders` and `passwordpolicy_webhook_endpoints` tables.
- Added the `url`, `authType`, `authToken`, `headers`, and `framing` columns to the `passwordpolicy_siem_forwarders` table, and relaxed `host` and `port` to nullable so an HTTP forwarder can omit them.
- Added the `pp:audit-view`, `pp:audit-verify`, `pp:audit-export`, `pp:siem-manage`, and `pp:webhooks-manage` permissions.
- The audit chain internals now run on `craftpulse/craft-audit-kit`, a new hard dependency shared with the rest of the CraftPulse estate, with no change to the schema, the canonical payload, or any existing row hash.
- A failed inline audit chain write is retried through a queue job with a jittered backoff, and logged at error level with its full payload if the retry budget runs out (Enterprise).

### Development
- Added fluent render builders on `craft.passwordPolicy`: `passwordField()`, `requirementList()`, `strengthMeter()`, `requirementsHint()`, `passwordWidget()`, `loginForm()`, `passwordChangeForm()`, and `passwordResetForm()` (Pro).
- Added the `requirements()`, `requirementsText()`, and `requirementRules()` data accessors on `craft.passwordPolicy`, available on every edition.
- Added a framework-free JavaScript client that any builder registers automatically when live validation, visibility toggling, or submit gating is on, so a consumer site needs no build step (Pro).
- Added the `password-policy/validation/validate` endpoint, which scores and validates a candidate password and drives both the control panel indicator and the front-end builders.
- Added `craftpulse\passwordpolicy\controllers\front\PasswordChangeController`, a logged-in password change flow that verifies the current password and destroys the user's other sessions.
- Added a read-only REST API at `password-policy/api/v1/`, exposing a user's password status, a user's resolved policy, and a redacted paginated slice of the audit log (Enterprise).
- The REST API authenticates with a Bearer token, is limited to 60 requests per token per minute, stays off until `apiEnabled` is on, and answers the same uniform 404 below Enterprise as it does when disabled (Enterprise).
- Added the `craft.passwordPolicy` variable handle alongside the existing `craft.passwordpolicy` handle, both of which keep working permanently.
- `password-policy/validation/validate` is rate-limited to a burst of 60 requests per IP refilling over 60 seconds, and answers `429 Too Many Requests` beyond that.
- `password-policy/validation/validate` does not run a live breach lookup for anonymous callers, returning the `hibp` rule unverified while `craftpulse\passwordpolicy\validators\HibpValidator` still refuses a breached password on save.
- `password-policy/validation/validate` scores at most the first 160 characters of the submitted value, matching `craft\validators\UserPasswordValidator::MAX_PASSWORD_LENGTH`, while the length rules still measure the whole value.
- Renamed the `pwned` and `pwnedFailMode` settings to `hibp` and `hibpFailMode`, with the legacy keys still accepted from `config/password-policy.php` behind a logged deprecation warning.
- Deprecated `craftpulse\passwordpolicy\services\PasswordService::pwned()` in favour of `craftpulse\passwordpolicy\services\PasswordService::hibp()`.

### Extensibility
- Added the `craftpulse\passwordpolicy\PasswordPolicy::EVENT_PASSWORD_CHANGED`, `EVENT_PASSWORD_VALIDATION`, `EVENT_BREACH_DETECTED`, `EVENT_NEW_DEVICE_DETECTED`, `EVENT_GROUP_ALERT_DISPATCHED`, and `EVENT_ACCOUNT_INACTIVE` events.
- Added the `craftpulse\passwordpolicy\services\PolicyService::EVENT_BEFORE_SAVE_POLICY` and `craftpulse\passwordpolicy\services\PolicyService::EVENT_AFTER_SAVE_POLICY` events.
- Added the `craftpulse\passwordpolicy\services\RegistrationService::EVENT_USER_REGISTERED`, `craftpulse\passwordpolicy\services\AlertCooldownService::EVENT_ALERT_COOLDOWN_FIRED`, `craftpulse\passwordpolicy\services\AuditLogService::EVENT_AUDIT_CHAIN_ROTATED`, `craftpulse\passwordpolicy\services\WebhookService::EVENT_WEBHOOK_DELIVERY_ATTEMPT`, and `craftpulse\passwordpolicy\jobs\AuditExportJob::EVENT_AUDIT_EXPORT_COMPLETE` events.
- Added `craftpulse\passwordpolicy\integrations\AuthKitAuditSink`, which lands every login, registration, passkey, session-revocation, and SCIM event Auth Kit emits on the audit log when Auth Kit is installed (Enterprise).
- Added `craftpulse\passwordpolicy\services\StrengthService`, `craftpulse\passwordpolicy\services\GeoIpService`, `craftpulse\passwordpolicy\services\DeviceTrackingService`, `craftpulse\passwordpolicy\services\GroupAlertService`, `craftpulse\passwordpolicy\services\InactiveAccountService`, and `craftpulse\passwordpolicy\services\ApiTokenService`.
- Added `craftpulse\passwordpolicy\exceptions\EditionRequiredException`, thrown by the service and Twig-variable edition gates so integrators can catch a gate explicitly.
- Password Policy now emits `passwordpolicy.policy_saved`, `passwordpolicy.policy_deleted`, and `passwordpolicy.group_assignment_changed` onto the Audit Kit governance bus, in addition to writing its own audit log.
- Added an event catalogue with payload tables and example listeners at `docs/user/reference/events.md`.

### Administration
- Added Lite, Pro, and Enterprise editions, recorded in project config.
- Added the `craftpulse\passwordpolicy\elements\PolicyElement`, `craftpulse\passwordpolicy\elements\NotificationLogElement`, and `craftpulse\passwordpolicy\elements\AuditLogElement` element types, each with its own control panel index, sources, sort options, and condition rules.
- Added an "API tokens" screen for issuing and revoking REST API Bearer tokens, which surfaces a token's plaintext exactly once and then stores only its hash and an eight character prefix (Enterprise).
- Added the `passwordpolicy_api_tokens` table and the `pp:api-manage` permission.
- Added the nested `pp:blocklist-view` and `pp:blocklist-manage` permissions.
- Added the `password-policy/gc/run` console command, which runs retention and expiry housekeeping across every retention-managed table.
- Added the `auditLogRetentionDays`, `notificationLogRetentionDays`, and `passwordHistoryExpiryDays` retention settings, applied by `password-policy/gc/run`.
- Added the `password-policy/blocklist/update`, `password-policy/blocklist/import`, and `password-policy/blocklist/stats` console commands.
- Added the `password-policy/inactive/scan` console command, which queues the dormant-account scan and takes `--threshold` and `--mode` overrides for one-off runs (Pro).
- Added info tooltips citing NIST 800-63B, PCI-DSS, GDPR, and NIS2 to the settings screens.
- Redesigned the settings screens around a sidebar grouped under Policy, Validation, Monitoring, and Audit.
- Higher-edition functionality no longer renders on lower editions, so nav entries, settings sections, utilities, index columns, condition-rule options, and the permissions behind them are absent rather than disabled, and a direct hit on a higher-edition control panel URL answers 404.
- Every permission gating a Pro or Enterprise screen now registers only on that edition, so a lower edition's permissions screen lists no grant that leads nowhere, and stored grants survive a downgrade untouched.
- Settings screens now gate on `pp:manage-settings` instead of requiring an admin account, and `allowAdminChanges` governs writability only.
- The subnav now lists Policies before Settings when per-group policies are enabled.
- The whole blocklist controller is now Pro-gated rather than only its index and save actions, and Lite operators seed the bundled list with `password-policy/blocklist/update`, which runs on every edition.

### Accessibility
- Added a live region, `aria-describedby` linking the input to its requirement list, `aria-invalid` and `aria-busy` toggling, and a `role="progressbar"` strength meter to the front-end render builders (Pro).
- Added arrow key, Home, and End navigation to the policy edit screen's preset radio group (Pro).
- Color-only status indicators on the Password Security screen are now hidden from assistive technology, since the adjacent text already names the state.

### System
- Password Policy now requires Craft 5.9.15 or later.
- Removed the `siemEnabled`, `siemDestinationType`, `siemEndpointUrl`, `siemAuthType`, `siemAuthToken`, `siemCustomHeaders`, `siemIpHandling`, `siemDeviceHandling`, `webhooksEnabled`, and `webhooks` settings, none of which were ever read; each SIEM destination carries its own configuration on the forwarder row instead.
- Added `bjeavons/zxcvbn-php` and dropped `@zxcvbn-ts/core`, `@zxcvbn-ts/language-common`, and `@zxcvbn-ts/language-en`, cutting the control panel JavaScript bundle from about 1.65 MB to about 2.2 KB.
- Added the `passwordpolicy_known_devices` and `passwordpolicy_group_alert_subscriptions` tables, documented with the rest of the schema at `docs/user/reference/database-schema.md`.
- The control panel strength indicator now scores passwords server-side over `password-policy/validation/validate` rather than running the scoring engine in the browser.
- The control panel strength indicator now attaches to every `input[type="password"][autocomplete="new-password"]` that is not opted out with `data-pp-no-strength`, including the installer and set-password screens, rather than to `#newPassword` alone.

## 5.1.2 - 2026-05-02
### Fixed
- Fixed HIBP requests not enforcing TLS verification when a site-level `config/guzzle.php` had `verify => false`. The plugin now always verifies TLS on the Pwned Passwords API call regardless of the site's Guzzle defaults.

### Changed
- Bumped HIBP fail-open log level from `ERROR` to `WARNING`. A transient HIBP outage shouldn't trigger ERROR-level alerts in operator monitoring.
- `PasswordPolicy::log()` now strips sensitive keys (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`) from logged params as defense-in-depth for third-party listener authors.

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
