# Editions

Password Policy ships three editions from a single 5.2.0 codebase. Lite is free; Pro and Enterprise are paid upgrades through the Craft Plugin Store. **Enterprise is not yet built** — it ships alongside Lite + Pro in the 5.2.0 release once Phase G work lands. The settings table and feature list below describe what each edition will surface at 5.2.0 release.

| Edition | Price | Focus |
|---------|-------|-------|
| **Lite** | Free | Baseline policy enforcement, HIBP at change time, strength meter, retention/expiry, force-change-on-first-login |
| **Pro** | ~$149 | Per-group policies + presets, password history, advanced validators, blocklist editor, notifications, front-end Twig render-builder surface, HIBP-on-login |
| **Enterprise** | ~$299 | (Phase G) Hash-chained audit log, compliance dashboard, SIEM forwarders, webhooks, API tokens |

## Edition helpers

```php
PasswordPolicy::$plugin->getIsLite();        // True only on Lite
PasswordPolicy::$plugin->getIsPro();         // True for Pro AND Enterprise (>=)
PasswordPolicy::$plugin->getIsEnterprise();  // True only for Enterprise

// Underlying Craft license — relevant for affordances that require user groups.
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
| Password history | | ✓ | ✓ |
| Per-group named policies + presets | | ✓ | ✓ |
| Sequential / repeated / contextual / blocklist validators | | ✓ | ✓ |
| Custom blocklist editor (CP page) | | ✓ | ✓ |
| Email notifications (expiry, breach, etc.) | | ✓ | ✓ |
| Hash-chained audit log | | | ✓ (Phase G) |
| Compliance dashboard | | | ✓ (Phase G) |
| SIEM forwarders + webhooks | | | ✓ (Phase G) |
| API token management | | | ✓ (Phase G) |

`PasswordChangedEvent`, `PasswordValidationEvent`, `UserRegisteredEvent`, and `BreachDetectedEvent` are part of every edition — third-party modules can subscribe regardless of license. See [`reference/events.md`](reference/events.md).

User-state capture (`passwordpolicy_user_state` table — last breach check, breached-recent flag, pending change reason) ships on every edition. Pro/Enterprise expose more of it through the user index columns; Lite writes the same rows but doesn't surface them in the CP. Upgrading from Lite to Pro retains the full audit trail rather than starting from scratch on the upgrade.

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

### Pro settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enablePerGroupPolicies` | `bool` | `false` | Resolve policies per user-group via the named-policy CRUD. When off, all users see the global policy. |
| `passwordHistoryCount` | `int` | `0` | Previous bcrypt hashes to compare against (0 disables, max 24). |
| `passwordHistoryExpiryDays` | `int` | `365` | Days to retain history rows before GC purges them. |
| `checkSequentialChars` | `bool` | `false` | Reject passwords with 3+ sequential ASCII or keyboard-row characters. |
| `checkRepeatedChars` | `bool` | `false` | Reject passwords with 3+ repeated characters. |
| `checkContextual` | `bool` | `false` | Reject passwords containing username, email, name, or site name. |
| `checkCommonPasswords` | `bool` | `false` | Reject passwords matching the bundled blocklist. |
| `complexityMode` | `string` | `'individual'` | `'individual'` runs each toggle separately; `'minimum'` requires X-of-4 character types. |
| `minimumCharacterTypes` | `int` | `0` | When `complexityMode = 'minimum'`, requires this many types (0–4). |
| `enableHibpOnLogin` | `bool` | `true` | Re-check the user's password against HIBP every login. |
| `expiryReminderDays` | `int` | `14` | Days before expiry to send the reminder notification. |
| `notificationLogRetentionDays` | `int` | `30` | Days to retain notification dedup-log rows. |

### Enterprise settings (Phase G)

These keys persist now but the matching feature surfaces ship in Phase G. Lite/Pro installs cannot save these via the CP — the settings save-action strip block enforces it.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enableAuditLog` | `bool` | `false` | Enable hash-chained audit logging. |
| `auditLogRetentionDays` | `int` | `365` | Days to retain audit-log rows before GC purges them. |
| `enableNewDeviceAlerts` | `bool` | `false` | Email + audit on new-device login (Phase G). |
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
- **Pro `NIST_800_63B` preset (`minLength = 15`, `hibp = true`, `checkCommonPasswords = true`, no composition rules, no rotation)** satisfies §3.1.1.2 SHALL requirements for memorized secrets. §3.2.2 rate-limiting at ≤100 consecutive failed attempts is delegated to Craft core (`maxInvalidLogins` site config — the default `5` already satisfies the ceiling).

Rev. 4 explicitly forbids composition rules (`SHALL NOT impose other composition rules`) and explicitly forbids periodic rotation (`SHALL NOT require subscribers to change passwords periodically`). The `cases`, `numbers`, `symbols`, and `expiryAmount` settings remain available because other frameworks require them (PCI DSS §8.3.6 mandates numeric + alphabetic; §8.3.9 mandates 90-day rotation). Mixing the two stances is fine — pick the preset that matches the framework your audit pack maps to. **Do not market the NIST preset as "compliant" with frameworks that require composition + rotation.** The four bundled presets (`NIST_800_63B`, `OWASP_ASVS`, `STRICT_ENTERPRISE`, `PCI_DSS_V4`) each map to their own framework — choosing one is a framework commitment.

### Phrasing discipline

These docs and the Plugin Store listing follow a specific phrasing discipline for compliance claims:

- Never write **"compliant with"** or **"certified"** about a framework. Certification requires an auditor; we ship technical measures.
- Write **"provides specific technical measures that controllers can rely on as part of their [framework] obligations"** or **"evidence and controls aligned with [specific clause]"** instead.
- Cite specific clause numbers (NIS2 Article 21(2)(g); ISO 27002:2022 A.8.15; SOC 2 CC7.2; PCI DSS §10.2) rather than framework names alone — auditors read the clause text, not the marketing.

## Edition gating rules

The plugin layers edition gates as defense-in-depth — the UI hides; the controller strips; the service-layer methods that consume edition-gated settings short-circuit on Lite. A bug at any one layer doesn't expose Pro/Enterprise behavior on Lite.

- **Migrations** run on every edition. Schema is identical regardless of license — Enterprise upgrades retain the full audit trail.
- **Settings model** ships every property regardless of edition. Values persist in project config; the CP UI is what's gated.
- **CP templates** check `getIsPro()` / `getIsEnterprise()` to render or hide edition-gated affordances. Lite admins see "Pro" badges on locked subnav items.
- **`SettingsController::actionSave`** unconditionally `unset()`s edition-gated keys for sub-edition saves before persisting — even crafted POST payloads carrying Pro keys can't survive on a Lite install.
- **Service-layer gates** apply to features whose execution would change behavior, not data capture. Audit log writes go through `AuditLogService::logEvent()` which gates on Enterprise. Per-group policy resolution runs only when `enablePerGroupPolicies = true` AND `getIsPro()` returns true.
- **Front-end Twig builders** degrade gracefully — Lite calls fall back to the global policy resolution path; no `403`s on the front-end.
- **HIBP-on-login** registers its `User::EVENT_BEFORE_AUTHENTICATE` listener only on Pro+ installs. Lite installs simply don't fire it.
