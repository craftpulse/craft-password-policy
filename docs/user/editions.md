# Editions

Password Policy ships three editions from a single 5.2.0 codebase. Edition selection and licensing happen through the Craft Plugin Store.

| Edition | Focus |
|---------|-------|
| **Lite** | Baseline policy enforcement, HIBP at change time, strength meter, common-password blocklist toggle, password history (global), expiry reminder emails (stock template), retention/expiry, force-change-on-first-login, device tracking (capture) |
| **Pro** | Per-group named policies + one-click compliance presets (NIST / OWASP / PCI-DSS / CIS / Strict Enterprise), advanced validators (sequential / repeated / contextual), minimum change interval, blocklist editor, notification template editor + activity log + resend, group alerts, dormant-account handling, front-end Twig render-builder surface, HIBP-on-login |
| **Enterprise** | Hash-chained audit log, compliance dashboard, SIEM forwarders, signed webhooks, audit export, read-only REST API + API tokens, IP geolocation, new-device alert emails |

Each feature page states its own edition requirement, which is the authoritative statement for that feature.

## Edition helpers

```php
PasswordPolicy::$plugin->getIsLite();        // True only on Lite
PasswordPolicy::$plugin->getIsPro();         // True for Pro AND Enterprise (>=)
PasswordPolicy::$plugin->getIsEnterprise();  // True only for Enterprise

// Underlying Craft license, relevant for affordances that require user groups.
PasswordPolicy::$plugin->isCraftSolo();          // Solo edition (single user, no groups)
PasswordPolicy::$plugin->isCraftTeamOrBetter();  // Team / Pro / Enterprise
```

`PasswordChangedEvent`, `PasswordValidationEvent`, `UserRegisteredEvent`, and `BreachDetectedEvent` are part of every edition. Third-party modules can subscribe regardless of license. See [`reference/events.md`](reference/events.md).

User-state capture (`passwordpolicy_user_state` table, last breach check, breached-recent flag, pending change reason) ships on every edition. Pro/Enterprise expose more of it through the user index columns; Lite writes the same rows but doesn't surface them in the CP. Upgrading from Lite to Pro retains the full audit trail rather than starting from scratch on the upgrade.

## Settings

All settings persist in project config regardless of edition. The CP UI hides settings that don't apply to the current edition; `SettingsController::actionSave` strips edition-gated keys on save as a defense-in-depth check, even if the UI conditional drifts.

### Lite settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `minLength` | `int` | `6` | Minimum password length. Cannot be lower than 6 (Craft's own floor). |
| `maxLength` | `int` | `0` | Maximum password length. `0` disables the cap. |
| `cases` | `bool` | `false` | Require mixed case. |
| `numbers` | `bool` | `false` | Require at least one digit. |
| `symbols` | `bool` | `false` | Require at least one special character. |
| `hibp` | `bool` | `false` | Check passwords against the HIBP breach database at change time. |
| `hibpFailMode` | `string` | `'open'` | `'open'` accepts when API unreachable, `'closed'` rejects. |
| `showStrengthIndicator` | `bool` | `false` | Render the strength meter on CP password fields. |
| `forceChangeOnFirstLogin` | `bool` | `false` | New users must change their password on first login. |
| `expiryAmount` | `?int` | `null` | Number of `expiryPeriod` units before expiry. `null` disables. |
| `expiryPeriod` | `string` | `'day'` | `'day'`, `'week'`, `'month'`, or `'year'`. |
| `cspNonce` | `bool` | `false` | Generate a CSP nonce for the strength-indicator script tag. |
| `retentionUtilities` | `bool` | `false` | Show the Retention CP utility for ad-hoc bulk operations. |
| `passwordHistoryCount` | `int` | `0` | Previous bcrypt hashes to compare against (0 disables, max 24). Per-group overrides require Pro. |
| `passwordHistoryExpiryDays` | `int` | `365` | Days to retain history rows before GC purges them. |
| `expiryReminderDays` | `int` | `14` | Days before expiry to send the reminder notification (stock template on Lite; Pro adds the editor + activity log + resend). |
| `checkCommonPasswords` | `bool` | `false` | Reject passwords matching the bundled blocklist. |

### Pro settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enablePerGroupPolicies` | `bool` | `false` | Resolve policies per user-group via the named-policy CRUD. When off, all users see the global policy. |
| `checkSequentialChars` | `bool` | `false` | Reject passwords with 3+ sequential ASCII or keyboard-row characters. |
| `checkRepeatedChars` | `bool` | `false` | Reject passwords with 3+ repeated characters. |
| `checkContextual` | `bool` | `false` | Reject passwords containing username, email, name, or site name. |
| `complexityMode` | `string` | `'individual'` | `'individual'` runs each toggle separately; `'minimum'` requires X-of-4 character types. |
| `minimumCharacterTypes` | `int` | `0` | When `complexityMode = 'minimum'`, requires this many types (0-4). |
| `enableHibpOnLogin` | `bool` | `true` | Re-check the user's password against HIBP every login. |
| `notificationLogRetentionDays` | `int` | `30` | Days to retain notification dedup-log rows. |
| `minChangeIntervalHours` | `int` | `0` | Hours that must elapse between two password changes for the same account. `0` disables. No global CP field; per-policy overrides have one. See [Minimum change interval](./features/min-change-interval.md). |
| `inactiveAccountsEnabled` | `bool` | `false` | Whether dormant-account handling is on. No CP field. See [Dormant accounts](./features/dormant-accounts.md). |
| `inactiveThresholdDays` | `int` | `90` | Days of inactivity before an account counts as dormant. No CP field. |
| `inactiveAction` | `string` | `'report'` | `'report'`, `'notify'`, or `'suspend'`. No CP field. |
| `inactiveNotifyAdmin` | `bool` | `false` | Also alert the admin per actioned dormant account. No CP field. |

### Enterprise settings

Lite/Pro installs cannot save these via the CP: the settings save-action strip block enforces it.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enableAuditLog` | `bool` | `false` | Enable hash-chained audit logging. |
| `auditLogRetentionDays` | `int` | `365` | Days to retain audit-log rows before GC purges them. |
| `enableNewDeviceAlerts` | `bool` | `false` | Email the user on a new-device sign-in. No CP field. Device capture itself runs on every edition. See [Device tracking](./features/device-tracking.md). |
| `deviceRetentionDays` | `int` | `180` | Days to retain known-device records. No CP field. |
| `geoIpEnabled` | `bool` | `false` | Resolve the country of each audit event's IP. Country code only; the raw IP is never stored. Carries a CC BY 4.0 attribution obligation, see [IP geolocation](./features/geoip.md). |
| `adminAlertEmail` | `?string` | `null` | Email address (env var) for admin security alerts. |
| `adminAlertEvents` | `?array` | `null` | Audit event types that trigger admin alerts. |
| `apiEnabled` | `bool` | `false` | Enable the read-only REST API. No CP field: set it in `config/password-policy.php`. See [REST API](./reference/rest-api.md). |

#### Declared but not consumed

The settings below are declared on the settings model and stripped from a sub-Enterprise save, but nothing in the plugin reads them. They are leftovers from the 5.2.0 development line, when SIEM forwarding and webhook delivery were configured as one global destination. Both features shipped as multi-destination registries instead, and each destination carries its own configuration row.

Setting any of these has no effect. They are listed here so the table matches the settings model, not because they do anything.

| Setting | Type | Default | What actually applies instead |
|---------|------|---------|-------------------------------|
| `siemEnabled` | `bool` | `false` | Nothing gates forwarding globally. A forwarder forwards when its own **Enabled** switch is on and its circuit breaker is closed, on an Enterprise install. See [SIEM forwarders](./features/siem-forwarders.md). |
| `siemDestinationType` | `string` | `'syslog'` | Each forwarder row's own protocol (`syslog-tls` or `http`). |
| `siemEndpointUrl` | `?string` | `null` | Each forwarder row's own URL, or host and port for syslog. |
| `siemAuthType` | `string` | `'bearer'` | Each forwarder row's own auth headers. |
| `siemAuthToken` | `?string` | `null` | Each forwarder row's own auth headers, encrypted at rest. |
| `siemCustomHeaders` | `?array` | `null` | Each forwarder row's own headers. |
| `siemIpHandling` | `string` | `'masked'` | Nothing. The audit log stores `ipHash` only, so there is no raw IP for a forwarder to shape. |
| `siemDeviceHandling` | `string` | `'label'` | Nothing. |
| `webhooksEnabled` | `bool` | `false` | Nothing gates delivery globally. An endpoint receives when its own **Enabled** switch is on and its circuit breaker is closed, on an Enterprise install. See [Webhooks](./features/webhooks.md). |
| `webhooks` | `array` | `[]` | The `passwordpolicy_webhook_endpoints` table, managed from **Password Policy → Webhooks** or from `password-policy/webhook/create`. |

## Compliance notes

### NIST 800-63B Rev. 4 alignment

NIST SP 800-63B Rev. 4 (finalised 31 July 2025) sets a 15-character minimum for single-factor authentication and an 8-character minimum for the password component of a multi-factor authenticator. The plugin handles both cases honestly:

- **Lite default (`minLength = 6`)** is below either NIST minimum. Sites running on the Lite default are not in single-factor NIST conformance; they're explicitly the "site picks its own floor" case. Raise `minLength` to 8 to land on the MFA-component minimum (paired with Craft's own MFA, when configured), or to 15 for the single-factor minimum.
- **Lite installs can hand-configure the §3.1.1.2 SHALL set**: `minLength = 15` + `hibp = true` + `checkCommonPasswords = true` + composition/expiry switches off. The settings are universal; what's Pro-gated is the one-click preset that applies the set as a single named-framework commitment.
- **`NIST_800_63B` preset (`minLength = 15`, `hibp = true`, `checkCommonPasswords = true`, no composition rules, no rotation)** is the Pro one-click application of §3.1.1.2 SHALL for memorized secrets. Apply globally on Pro via the Compliance Presets settings page; apply per-group on Pro via named-policy CRUD. §3.2.2 rate-limiting at ≤100 consecutive failed attempts is delegated to Craft core (`maxInvalidLogins` site config: the default `5` already satisfies the ceiling).

Rev. 4 explicitly forbids composition rules (`SHALL NOT impose other composition rules`) and explicitly forbids periodic rotation (`SHALL NOT require subscribers to change passwords periodically`). The `cases`, `numbers`, `symbols`, and `expiryAmount` settings remain available because other frameworks require them (PCI DSS §8.3.6 mandates numeric + alphabetic; §8.3.9 mandates 90-day rotation; CIS Controls v8 Safeguard 5.2 references annual expiration via the CIS Password Policy Guide). Mixing stances is fine, pick the preset that matches the framework your audit pack maps to. The five bundled presets (`NIST_800_63B`, `OWASP_ASVS`, `PCI_DSS_V4`, `CIS_CONTROLS_V8`, `STRICT_ENTERPRISE`) each map to their own framework, and choosing one is a framework commitment. A preset does not make you conformant with a framework it does not map to, so if your audit covers two frameworks with conflicting requirements, split them across per-group policies rather than looking for a preset that satisfies both.

### CIS Controls v8 alignment

CIS Controls v8 Safeguard 5.2 (IG1 / IG2 / IG3) sets the password length floor at **14 characters for password-only accounts and 8 characters for MFA-enabled accounts**. The CIS Password Policy Guide companion adds last-5 history, continuous breach checking (HIBP-equivalent), a deny-list of common/poor passwords, and one-year expiration with forced rotation on suspected compromise.

The `CIS_CONTROLS_V8` preset defaults to **14 chars** (the safer floor) because the plugin can't reliably detect MFA presence at preset-apply time. Sites running Craft's native TOTP get a stricter-than-CIS-minimum policy, which CIS treats as conformant.

The CIS preset's 365-day rotation deliberately diverges from NIST 800-63B Rev. 4 (which forbids periodic rotation). CIS-aligned compliance buyers (US federal contractors using CIS as the actionable companion to NIST, CIS Benchmark shops) expect annual rotation here. Pick the preset that matches the framework you're aligning to; don't apply both NIST and CIS to the same global policy.

The CIS preset applies globally on Pro via the Compliance Presets settings page, and per-group via the named-policy CRUD. Lite installs can hand-configure the same field set, what's Pro-gated is the one-click apply as a framework-named commitment.

## Edition gating rules

**Gating hides, it never badges.** A lower edition renders no trace of a higher-edition feature: no disabled fields, no locked sidebar rows, no upsell callouts, and no instruction text naming a surface the edition can't reach. Discovery happens through the plugin docs and the Plugin Store listing, not through dead controls in the CP.

The plugin layers those gates as defense-in-depth: the UI hides; the controller 404s; the save action strips; the service-layer methods that consume edition-gated settings short-circuit. A bug at any one layer doesn't expose Pro/Enterprise behavior on Lite.

- **Migrations** run on every edition. Schema is identical regardless of license, so Enterprise upgrades retain the full audit trail.
- **Settings model** ships every property regardless of edition. Values persist in project config; the CP UI is what's gated.
- **CP templates** check `getIsPro()` / `getIsEnterprise()` to render or omit edition-gated affordances. A Lite admin never sees the Pro-only Group Policies / Compliance Presets / Validators (advanced) settings, and a Pro admin never sees the Enterprise-only fields. Whole-screen higher-edition settings sections are omitted from the settings sidebar too. Mixed pages (Configuration, Password Rules, Password History, Validators, Audit Logging) render on every edition and simply omit their higher-edition fields, including any instruction copy that would name a higher-edition surface.
- **CP nav** omits every higher-edition subnav entry, and **utilities** (compliance dashboard, audit schema, audit export) aren't registered below Enterprise, so they don't appear in the utilities index.
- **Permissions** for higher-edition surfaces register only on those editions, so a lower edition's permissions screen never lists a grant that leads nowhere. Grants already stored survive a downgrade and take effect again on upgrade.
- **CP controllers** behind a higher-edition screen answer **404** on lower editions (`yii\web\NotFoundHttpException`, via `craftpulse\passwordpolicy\base\RequiresEditionTrait`), not 403. The screen doesn't exist on that edition and the nav never offered it, so a bookmarked or hand-typed URL behaves like any other nonexistent route. A 403 would confirm the screen is there.
- **The read-only REST API** (Enterprise) returns the same uniform JSON 404 below Enterprise that it returns when `apiEnabled` is off. No existence oracle, no edition named in the body.
- **`SettingsController::actionSave`** unconditionally `unset()`s edition-gated keys for sub-edition saves before persisting. Even crafted POST payloads carrying Pro keys can't survive on a Lite install.
- **Service-layer gates** apply to features whose execution would change behavior, not data capture. Audit log writes go through `AuditLogService::logEvent()` which gates on Enterprise. Per-group policy resolution runs only when `enablePerGroupPolicies = true` AND `getIsPro()` returns true.
- **Front-end Twig render builders** (`passwordField`, `requirementList`, `strengthMeter`, `requirementsHint`, `passwordWidget`, `loginForm`, `passwordChangeForm`, `passwordResetForm`) throw `craftpulse\passwordpolicy\exceptions\EditionRequiredException` (extends `\RuntimeException`) on Lite via `PasswordPolicyVariable::_assertProForBuilders()`, Twig surfaces the exception in dev mode and renders the friendly error template in production. Lite consumers build their own markup against the universal data accessors (`requirements`, `requirementsText`, `requirementRules`). Per-group resolution gates separately inside `PolicyResolverService`.
- **HIBP-on-login** registers its `User::EVENT_BEFORE_AUTHENTICATE` listener only on Pro+ installs. Lite installs simply don't fire it.
- **Force password reset** splits along the mass / per-user line. The **mass** reset is universal: the "Force Reset Passwords" action on the **Password Retention** utility and the `password-policy/retention/force-reset-passwords` console command both flag every account already past the configured expiry window, on every edition, gated by `pp:force-reset-passwords`. The **per-user** reset is Pro: the `ForcePasswordReset` bulk element action on the Users index, the "Force password reset" item in the user-edit action menu, and the Actions pane on the user-edit Password Security screen all target named accounts whether or not their passwords have expired, and all sit behind `pp:user-force-reset`, which registers on Pro+ only. `UserSecurityController::actionForceReset()` gates on edition before permission, so a POST on Lite answers 404. The Password Security screen itself stays universal, it just omits the pane.
- **A non-admin can never force a password reset on an admin**, on any edition. `pp:user-force-reset` is grantable to non-admins, so the guard sits below the permission: the Password Security pane doesn't render the button, the bulk element action refuses the run rather than partially applying it, and the POST handler answers 403. An admin acting on another admin is allowed.
