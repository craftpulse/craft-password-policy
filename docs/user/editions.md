# Editions

Password Policy ships three editions from a single 5.2.0 codebase. Lite is free; Pro and Enterprise are paid upgrades through the Craft Plugin Store.

| Edition | Price | Focus |
|---------|-------|-------|
| **Lite** | Free | Baseline policy enforcement, HIBP at change time, strength meter, common-password blocklist toggle, password history (global), expiry reminder emails (stock template), retention/expiry, force-change-on-first-login |
| **Pro** | ~$149 | Per-group named policies + one-click compliance presets (NIST / OWASP / PCI-DSS / CIS / Strict Enterprise), advanced validators (sequential / repeated / contextual), blocklist editor, notification template editor + activity log + resend, front-end Twig render-builder surface, HIBP-on-login |
| **Enterprise** | ~$299 | Hash-chained audit log, compliance dashboard, SIEM forwarders, signed webhooks, audit export, API tokens |

## Edition helpers

```php
PasswordPolicy::$plugin->getIsLite();        // True only on Lite
PasswordPolicy::$plugin->getIsPro();         // True for Pro AND Enterprise (>=)
PasswordPolicy::$plugin->getIsEnterprise();  // True only for Enterprise

// Underlying Craft license, relevant for affordances that require user groups.
PasswordPolicy::$plugin->isCraftSolo();          // Solo edition (single user, no groups)
PasswordPolicy::$plugin->isCraftTeamOrBetter();  // Team / Pro / Enterprise
```

## Feature comparison

| Feature | Lite | Pro | Enterprise |
|---------|:----:|:---:|:----------:|
| Length, complexity, expiry rules | ✓ | ✓ | ✓ |
| HIBP check at password change | ✓ | ✓ | ✓ |
| HIBP check on every login | | ✓ | ✓ |
| CP strength meter (zxcvbn) | ✓ | ✓ | ✓ |
| Front-end Twig render builders (consumer-site forms) | | ✓ | ✓ |
| Force change on first login | ✓ | ✓ | ✓ |
| Force-reset element action | | ✓ | ✓ |
| Change-password element action | ✓ | ✓ | ✓ |
| Send-reset-email element action | ✓ | ✓ | ✓ |
| Password history (global, 0-24) | ✓ | ✓ | ✓ |
| Per-group named policies + history overrides | | ✓ | ✓ |
| Compliance preset one-click apply (NIST / OWASP / PCI-DSS / CIS / Strict) | | ✓ | ✓ |
| Expiry-reminder email (cron + queue) | ✓ stock template | ✓ editor + resend | ✓ |
| Breach-detected email | | ✓ | ✓ |
| New-device tracking (capture) | ✓ | ✓ | ✓ |
| New-device alert email + audit | | | ✓ |
| Notification activity log (CP screen) | | ✓ | ✓ |
| Sequential / repeated / contextual validators | | ✓ | ✓ |
| Common-password blocklist toggle | ✓ | ✓ | ✓ |
| Custom blocklist editor (CP page) | | ✓ | ✓ |
| Hash-chained audit log | | | ✓ |
| Compliance dashboard | | | ✓ |
| SIEM forwarders + signed webhooks | | | ✓ |
| Audit export (signed download) | | | ✓ |
| API token management | | | ✓ |

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

### Enterprise settings

Lite/Pro installs cannot save these via the CP: the settings save-action strip block enforces it.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enableAuditLog` | `bool` | `false` | Enable hash-chained audit logging. |
| `auditLogRetentionDays` | `int` | `365` | Days to retain audit-log rows before GC purges them. |
| `enableNewDeviceAlerts` | `bool` | `false` | Email + audit on new-device login. |
| `deviceRetentionDays` | `int` | `180` | Days to retain known-device records. |
| `adminAlertEmail` | `?string` | `null` | Email address (env var) for admin security alerts. |
| `adminAlertEvents` | `?array` | `null` | Audit event types that trigger admin alerts. |
| `siemEnabled` | `bool` | `false` | Forward audit events to SIEM. |
| `siemDestinationType` | `string` | `'syslog'` | `'syslog'`, `'http'`, or `'event'`. |
| `siemEndpointUrl` | `?string` | `null` | SIEM HTTP endpoint URL (env var). |
| `siemAuthType` | `string` | `'bearer'` | `'bearer'`, `'basic'`, or `'header'`. |
| `siemAuthToken` | `?string` | `null` | SIEM auth token (env var, never echoed after save). |
| `siemCustomHeaders` | `?array` | `null` | Custom SIEM HTTP headers. |
| `siemIpHandling` | `string` | `'masked'` | `'masked'`, `'hashed'`, `'raw'`, or `'excluded'`. |
| `siemDeviceHandling` | `string` | `'label'` | `'label'` or `'excluded'`. |
| `webhooksEnabled` | `bool` | `false` | Enable outbound HMAC-signed webhooks. |
| `webhooks` | `array` | `[]` | Webhook configurations. |
| `apiEnabled` | `bool` | `false` | Enable API token management. |

## Compliance notes

### NIST 800-63B Rev. 4 alignment

NIST SP 800-63B Rev. 4 (finalised 31 July 2025) sets a 15-character minimum for single-factor authentication and an 8-character minimum for the password component of a multi-factor authenticator. The plugin handles both cases honestly:

- **Lite default (`minLength = 6`)** is below either NIST minimum. Sites running on the Lite default are not in single-factor NIST conformance; they're explicitly the "site picks its own floor" case. Raise `minLength` to 8 to land on the MFA-component minimum (paired with Craft's own MFA, when configured), or to 15 for the single-factor minimum.
- **Lite installs can hand-configure the §3.1.1.2 SHALL set**: `minLength = 15` + `hibp = true` + `checkCommonPasswords = true` + composition/expiry switches off. The settings are universal; what's Pro-gated is the one-click preset that applies the set as a single named-framework commitment.
- **`NIST_800_63B` preset (`minLength = 15`, `hibp = true`, `checkCommonPasswords = true`, no composition rules, no rotation)** is the Pro one-click application of §3.1.1.2 SHALL for memorized secrets. Apply globally on Pro via the Compliance Presets settings page; apply per-group on Pro via named-policy CRUD. §3.2.2 rate-limiting at ≤100 consecutive failed attempts is delegated to Craft core (`maxInvalidLogins` site config: the default `5` already satisfies the ceiling).

Rev. 4 explicitly forbids composition rules (`SHALL NOT impose other composition rules`) and explicitly forbids periodic rotation (`SHALL NOT require subscribers to change passwords periodically`). The `cases`, `numbers`, `symbols`, and `expiryAmount` settings remain available because other frameworks require them (PCI DSS §8.3.6 mandates numeric + alphabetic; §8.3.9 mandates 90-day rotation; CIS Controls v8 Safeguard 5.2 references annual expiration via the CIS Password Policy Guide). Mixing stances is fine, pick the preset that matches the framework your audit pack maps to. **Do not market a preset as "compliant" with frameworks it doesn't map to.** The five bundled presets (`NIST_800_63B`, `OWASP_ASVS`, `PCI_DSS_V4`, `CIS_CONTROLS_V8`, `STRICT_ENTERPRISE`) each map to their own framework, choosing one is a framework commitment.

### CIS Controls v8 alignment

CIS Controls v8 Safeguard 5.2 (IG1 / IG2 / IG3) sets the password length floor at **14 characters for password-only accounts and 8 characters for MFA-enabled accounts**. The CIS Password Policy Guide companion adds last-5 history, continuous breach checking (HIBP-equivalent), a deny-list of common/poor passwords, and one-year expiration with forced rotation on suspected compromise.

The `CIS_CONTROLS_V8` preset defaults to **14 chars** (the safer floor) because the plugin can't reliably detect MFA presence at preset-apply time. Sites running Craft's native TOTP get a stricter-than-CIS-minimum policy, which CIS treats as conformant.

The CIS preset's 365-day rotation deliberately diverges from NIST 800-63B Rev. 4 (which forbids periodic rotation). CIS-aligned compliance buyers (US federal contractors using CIS as the actionable companion to NIST, CIS Benchmark shops) expect annual rotation here. Pick the preset that matches the framework you're aligning to; don't apply both NIST and CIS to the same global policy.

The CIS preset applies globally on Pro via the Compliance Presets settings page, and per-group via the named-policy CRUD. Lite installs can hand-configure the same field set, what's Pro-gated is the one-click apply as a framework-named commitment.

### Phrasing discipline

These docs and the Plugin Store listing follow a specific phrasing discipline for compliance claims:

- Never write **"compliant with"** or **"certified"** about a framework. Certification requires an auditor; we ship technical measures.
- Write **"provides specific technical measures that controllers can rely on as part of their [framework] obligations"** or **"evidence and controls aligned with [specific clause]"** instead.
- Cite specific clause numbers (NIS2 Article 21(2)(g); ISO 27002:2022 A.8.15; SOC 2 CC7.2; PCI DSS §10.2) rather than framework names alone: auditors read the clause text, not the marketing.

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
- **Front-end Twig render builders** (`passwordField`, `requirementList`, `strengthMeter`, `requirementsHint`, `passwordWidget`, `loginForm`, `passwordChangeForm`, `passwordResetForm`) throw `craftpulse\passwordpolicy\exceptions\EditionRequiredException` (extends `\RuntimeException`) on Lite via `PasswordPolicyVariable::_assertProForBuilders()`, Twig surfaces the exception in dev mode and renders the friendly error template in production. The friendly consumer-form rendering surface is a Pro upgrade lever; Lite consumers roll their own markup against the universal data accessors (`requirements`, `requirementsText`, `requirementRules`). Per-group resolution gates separately inside `PolicyResolverService`.
- **HIBP-on-login** registers its `User::EVENT_BEFORE_AUTHENTICATE` listener only on Pro+ installs. Lite installs simply don't fire it.
