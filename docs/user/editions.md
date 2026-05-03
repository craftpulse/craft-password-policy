# Editions

Password Policy ships three editions from a single 5.2.0 codebase. Lite is free; Pro and Enterprise are paid upgrades through the Craft Plugin Store. **Enterprise is not yet built** — it ships alongside Lite + Pro in the 5.2.0 release once Phase G work lands. The settings table and feature list below describe what each edition will surface at 5.2.0 release.

| Edition | Price | Focus |
|---------|-------|-------|
| **Lite** | Free | Baseline policy enforcement, HIBP at change time, strength meter, retention/expiry, force-change-on-first-login |
| **Pro** | ~$149 | Per-group policies + presets, password history, advanced validators, blocklist editor, notifications, front-end Twig surface, HIBP-on-login, zxcvbn strength engine |
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
| Strength meter (rule-counting baseline) | ✓ | ✓ | ✓ |
| Strength meter (zxcvbn dictionary engine) | | ✓ | ✓ |
| Force change on first login | ✓ | ✓ | ✓ |
| Force-reset element action | | ✓ | ✓ |
| Change-password element action | ✓ | ✓ | ✓ |
| Send-reset-email element action | ✓ | ✓ | ✓ |
| Password history | | ✓ | ✓ |
| Per-group named policies + presets | | ✓ | ✓ |
| Sequential / repeated / contextual / blocklist validators | | ✓ | ✓ |
| Custom blocklist editor (CP page) | | ✓ | ✓ |
| Email notifications (expiry, breach, etc.) | | ✓ | ✓ |
| Front-end Twig render builders | | ✓ | ✓ |
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
| `useZxcvbnStrength` | `bool` | `false` | Use the `bjeavons/zxcvbn-php` engine for strength scoring instead of the rule-counting baseline. |
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

## Edition gating rules

The plugin layers edition gates as defense-in-depth — the UI hides; the controller strips; the service-layer methods that consume edition-gated settings short-circuit on Lite. A bug at any one layer doesn't expose Pro/Enterprise behavior on Lite.

- **Migrations** run on every edition. Schema is identical regardless of license — Enterprise upgrades retain the full audit trail.
- **Settings model** ships every property regardless of edition. Values persist in project config; the CP UI is what's gated.
- **CP templates** check `getIsPro()` / `getIsEnterprise()` to render or hide edition-gated affordances. Lite admins see "Pro" badges on locked subnav items.
- **`SettingsController::actionSave`** unconditionally `unset()`s edition-gated keys for sub-edition saves before persisting — even crafted POST payloads carrying Pro keys can't survive on a Lite install.
- **Service-layer gates** apply to features whose execution would change behavior, not data capture. Audit log writes go through `AuditLogService::logEvent()` which gates on Enterprise. Per-group policy resolution runs only when `enablePerGroupPolicies = true` AND `getIsPro()` returns true.
- **Front-end Twig builders** degrade gracefully — Lite calls fall back to the global policy resolution path; no `403`s on the front-end.
- **HIBP-on-login** registers its `User::EVENT_BEFORE_AUTHENTICATE` listener only on Pro+ installs. Lite installs simply don't fire it.
