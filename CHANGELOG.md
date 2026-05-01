# Release Notes for Password Policy

## Unreleased — 5.2.0

> Pro edition expansion. Introduces editions (Lite / Pro / Enterprise), per-group named policies, password history, advanced validators, audit logging infrastructure, and a redesigned settings UI.

### Added

- Plugin editions: Lite (default), Pro, Enterprise — gated via `project.yaml` (`edition: pro`)
- Per-group named policies (Pro) — CRUD manager at Password Policy → Policies for assigning override policies to user groups
- Tri-state rule overrides per policy (Off / Global / On) — explicit Off honored against global, "most-restrictive wins" across multi-group users
- 4 policy presets — NIST 800-63B, OWASP ASVS L1, PCI-DSS v4.0, Strict Enterprise — applied as starting templates
- Password history (Pro) — block reuse of the last N passwords (configurable count + retention)
- Advanced validators (Pro) — sequential characters, repeated characters, contextual data, common password blocklist
- HIBP fail mode setting — "open" (accept on API failure) or "closed" (reject on failure)
- HIBP TLS verification override — plugin-level requests force `verify => true` even when `config/guzzle.php` disables it globally
- Tabbed policy edit screen — General / Rules / Lifecycle
- Divergence indicators — blue left border on fields differing from the policy's preset, blue dot + "N changes" in the policies index
- "Restore preset defaults" button — re-apply the selected preset's values to a customized policy
- "Reset all to global" button — clear every override on the current policy in one click
- Override warnings — Craft-native `warning:` notices on numeric fields and HIBP fail mode when a policy value differs from global
- Element actions: Force Password Reset (Pro) for bulk operations on the Users index
- Element condition rules: Password Expired, Password Reset Required, Password Never Changed
- Twig variables — `craft.passwordpolicy.passwordStatus()`, `daysUntilExpiry()`, `isExpiring(N)`, `activeSessionCount()`
- AJAX validation endpoint at `password-policy/validate` for live password strength feedback
- New top-level **Blocklist** subnav (Pro) — single page housing the bundled-list stats with SecLists source citation, the "Update Common Passwords" cron-driven seed action, an admin-managed editable table for custom blocked words (diff-on-save via `forms.editableTableField`), and a "Check a word" tool that AJAX-queries whether any value is currently blocked (case-insensitive, common or custom)
- `SeedBlocklist` queue job — seeds the common-password blocklist in the background
- `pp:blocklist-view` permission — gates Blocklist page access (read-only is sufficient)
- `pp:blocklist-manage` permission — nested under `pp:blocklist-view`, gates edits to custom words and the "Update Common Passwords" seed action
- Custom CP icons for the password policy nav section
- Audit log table and `AuditLogService` (Enterprise — view/export gated to Enterprise)
- Info icon tooltips on all settings pages with NIST/PCI-DSS/GDPR references
- Garbage collection hook (`gc/run`) for retention/expiry housekeeping
- Group-deletion observability listener — logs which named policies lose an assignment when a Craft user group is deleted (seam for future Enterprise audit logging)
- New top-level **Notifications** subnav (Pro) between Blocklist and Settings — per-(notification, site) editable email templates with subject + plaintext body Twig sources, click-to-copy token chips for `{{ user }}`, `{{ daysUntilExpiry }}`, `{{ siteName }}`, env-var-aware sender overrides, and an AJAX test-send rendering against the current admin
- Storage table `passwordpolicy_notification_templates` — one row per (notificationKey, siteId) with a JSON `content` column (mirrors Craft 5's elements_sites content shape — race-free per-site editing, FK CASCADE on site delete)
- `Sites::EVENT_AFTER_SAVE_SITE` propagation listener — when a new site is added, copies primary-site notification rows into the new site so admins don't see a missing-template state on first edit (defensive try/catch never blocks the site save)
- `pp:notification-templates-manage` permission (Pro) — gates the Notifications page and all notification-template controllers actions
- `password-policy/notification/send-expiry-reminders [--user=<id>]` console command — enqueues `SendPasswordExpiryRemindersJob` (BaseBatchedJob, batchSize=100, ttr=300, canRetry≤5) which recomputes its recipient set per batch for natural retry idempotency. Lite returns `ExitCode::UNSPECIFIED_ERROR` with stderr "Pro edition required."
- `RegistrationService::register(array $params): User` — programmatic helper for consumer registration controllers. Resolves group **handles** (more dev-friendly than IDs) and pre-validates the proposed password against the resolved policy (Lite uses global; Pro resolves per-group via `PolicyResolverService`). Persists the user, assigns groups, optionally sends Craft's activation email, fires `UserRegisteredEvent` on success. Throws `\InvalidArgumentException` on missing required params, unknown group handles, or validation failures (with attribute-prefixed messages for clean surfacing in consumer forms).
- New `UserRegisteredEvent` (`craftpulse\passwordpolicy\events\UserRegisteredEvent`) — fired by `RegistrationService` after successful registration. Payload: `User $user`, `string[] $groups` (the group handles assigned), `bool $viaService = true`. Plaintext intentionally absent — already validated and persisted by event time.
- HIBP-on-login (Pro) — re-checks every signing-in user's password against the Have I Been Pwned breach database via the same k-anonymity protocol used at password-change time. Detection forces `passwordResetRequired = true` on the user, sends a `breach-detected` notification email, fires `BreachDetectedEvent`, and writes an Enterprise audit-log entry; the login itself is never blocked. Listens to `User::EVENT_BEFORE_AUTHENTICATE` (the only Craft 5 event with synchronous plaintext-in-scope access). 24-hour dedup cache keyed by `(userId, sha1Prefix)` prevents repeat notifications for daily-active users with the same password. **Privacy invariant**: never logs the plaintext, full SHA-1 hash, or bucket suffix — only the 5-char k-anonymity prefix and a "match found" boolean. Toggle via `enableHibpOnLogin` setting on the Configuration page (default on, gated to Pro).
- New `breach-detected` notification template seeded per (site) on upgrade and at fresh-install — editable through the existing Notifications subnav like `expiry-reminder`. Default copy explains the breach, what we already did (`passwordResetRequired`), and what the user should do (change the password, change it elsewhere if reused). Token: `{{ user }}`, `{{ siteName }}`, `{{ detectedAt }}`.
- New `BreachDetectedEvent` (`craftpulse\passwordpolicy\events\BreachDetectedEvent`) — fired by the HIBP-on-login listener on detection. Payload: `User $user`, `string $sha1Prefix` (5 chars uppercase, k-anonymity safe), `\DateTime $detectedAt`. Plaintext, full hash, and bucket suffix intentionally absent.
- New plugin setting `enableHibpOnLogin: bool` (default `true`, Pro). UI toggle on the Settings → Configuration page next to the existing HIBP-at-change-time fields.

### Changed

- Settings UI redesigned — sidebar grouped under Policy / Validation / Monitoring with edition badges
- `pwned` setting renamed to `hibp` (project config + DB) — migration handles the rename
- Subnav lists Policies before Settings (when per-group policies enabled)
- `Sequential characters` validator detects ASCII sequences (e.g. `pqr`, `xyz`) in addition to keyboard rows
- `lastPasswordChangeDate` queried directly to bypass `UserQuery::beforePrepare()` not selecting it
- Sensitive keys (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`) automatically stripped from plugin log entries
- Common password blocklist stored separately from custom dictionary (`source = 'common'` vs `'custom'`) — prevents flooding the admin UI
- Common-password validator emits source-aware error messages — bundled common entries return "too common, choose a more unique password"; custom-blocklist entries return "blocked, choose a different one"
- Removed the `BlocklistUtility` (was at Utilities → Password Blocklist) — its stats and "Update Common" affordances are absorbed into the new Blocklist subnav page, and the editable custom-word editor lives there too. Single mental model instead of split surfaces.

### Fixed

- `getIsLite()` no longer hardcoded to `return true` — uses `is(self::EDITION_LITE)`
- Validation order — content rules run before HIBP/history checks (avoids unnecessary API calls on weak passwords)
- Common password blocklist auto-seeds via queue when the toggle is enabled with an empty blocklist (previously failed silently)
- `expiryPeriod` no longer persisted on policy settings without an `expiryAmount`

## 5.1.1 - 2026-04-17
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
