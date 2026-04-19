# Phase 0 — Edition Infrastructure + Settings Model

## Overview

Phase 0 introduces the three-edition structure (Lite, Pro, Enterprise) and expands the settings model with all configuration properties needed across the full v5.2.0 release. No behavior changes — this is pure wiring.

## Editions

Password Policy ships three editions:

| Edition | Price | Focus |
|---------|-------|-------|
| **Lite** | Free | Global password policy, HIBP, strength indicator, retention/expiration |
| **Pro** | ~$149 | Password history, advanced validators, per-group policies, user index |
| **Enterprise** | ~$299 | Audit logging, anomaly detection, compliance, SIEM, API tokens |

### Edition Helpers

```php
PasswordPolicy::$plugin->getIsLite();       // Always true
PasswordPolicy::$plugin->getIsPro();         // True for Pro AND Enterprise
PasswordPolicy::$plugin->getIsEnterprise();  // True for Enterprise only
```

### Gating Rules

- **Migrations**: Run regardless of edition — all tables are created
- **Settings model**: All attributes exist regardless of edition — values persist in project config
- **Pro features**: Gated with `getIsPro()`
- **Enterprise features**: Gated with `getIsEnterprise()`
- **Templates**: Lock badges on lower editions
- **Controllers**: Strip edition-gated settings on save

## New Settings

All new settings default to off/0, ensuring zero behavior change on upgrade.

### Lite Settings (new)

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `pwnedFailMode` | `string` | `'open'` | HIBP failure behavior: `'open'` accepts when API unreachable, `'closed'` rejects |
| `forceChangeOnFirstLogin` | `bool` | `false` | Require new users to change password on first login |

### Pro Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `passwordHistoryCount` | `int` | `0` | Previous passwords to check (0 = disabled, max 24) |
| `passwordHistoryExpiryDays` | `int` | `365` | Days to retain history entries |
| `checkSequentialChars` | `bool` | `false` | Detect sequences like `abc`, `123` |
| `checkRepeatedChars` | `bool` | `false` | Detect repeats like `aaa` |
| `checkContextual` | `bool` | `false` | Check against username, email, site name |
| `checkCommonPasswords` | `bool` | `false` | Check against common password blocklist |
| `complexityMode` | `string` | `'individual'` | `'individual'` for per-toggle, `'minimum'` for X-of-4 |
| `minimumCharacterTypes` | `int` | `0` | Required character types when mode is `'minimum'` (0-4) |
| `enablePerGroupPolicies` | `bool` | `false` | Enable per-group policy overrides |
| `groupPolicies` | `?array` | `null` | Per-group policy overrides keyed by group UID |
| `expiryReminderDays` | `int` | `14` | Days before expiry to send reminder |
| `notificationLogRetentionDays` | `int` | `30` | Days to retain notification log entries |

### Enterprise Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enableAuditLog` | `bool` | `false` | Enable audit logging |
| `auditLogRetentionDays` | `int` | `365` | Days to retain audit log entries |
| `enableNewDeviceAlerts` | `bool` | `false` | Enable new device login alerts |
| `deviceRetentionDays` | `int` | `180` | Days to retain known device records |
| `adminAlertEmail` | `?string` | `null` | Email for admin security alerts (env var) |
| `adminAlertEvents` | `?array` | `null` | Events that trigger admin alerts |
| `siemEnabled` | `bool` | `false` | Enable SIEM forwarding |
| `siemDestinationType` | `string` | `'syslog'` | SIEM type: `'syslog'`, `'http'`, `'event'` |
| `siemEndpointUrl` | `?string` | `null` | SIEM HTTP endpoint (env var) |
| `siemAuthType` | `string` | `'bearer'` | SIEM auth: `'bearer'`, `'basic'`, `'header'` |
| `siemAuthToken` | `?string` | `null` | SIEM token (env var, never shown after save) |
| `siemCustomHeaders` | `?array` | `null` | Custom SIEM HTTP headers |
| `siemIpHandling` | `string` | `'masked'` | IP in SIEM: `'masked'`, `'hashed'`, `'raw'`, `'excluded'` |
| `siemDeviceHandling` | `string` | `'label'` | Device in SIEM: `'label'`, `'excluded'` |
| `webhooksEnabled` | `bool` | `false` | Enable webhook events |
| `webhooks` | `array` | `[]` | Webhook configurations |
| `apiEnabled` | `bool` | `false` | Enable API token management |

## Security Fix: HIBP TLS Verification

The Guzzle client for HIBP API calls now passes `'verify' => true` explicitly, preventing site-level `config/guzzle.php` from disabling TLS verification.

## Security Fix: Log Sensitive Key Stripping

The `PasswordPolicy::log()` method now strips sensitive keys (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`) from parameters before any logging occurs. This is a code-level filter, not a convention.

## Migration Notes

- **Schema version** bumped from `1.0.0` to `2.0.0`
- **Plugin version** bumped from `5.1.1` to `5.2.0-alpha.1`
- All new settings default to off/0 — zero behavior change on upgrade
- Existing settings are preserved unchanged
