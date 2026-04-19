# Phase 4 — Audit Logging Service + Craft Event Listeners

## Overview

Phase 4 adds comprehensive audit logging for password-related security events. The audit log records who, what, when, where, and outcome — without ever storing password data.

## AuditLogService

### `logEvent()`

Central logging method. Key behaviors:
- **Edition gated**: No-ops silently on Lite/Pro
- **Try/catch wrapped**: Never blocks the parent operation
- **Runtime-enforced detail allowlist**: `array_intersect_key()` strips any key not on the approved list
- **IP hashing**: Stores SHA-256 of IP, never raw
- **User identifier**: HMAC-SHA-256 of email using Craft's security key for post-deletion correlation

### Allowed Detail Keys

`deviceLabel`, `groupId`, `groupName`, `reason`, `violationType`, `source`, `outcome`, `method`, `failMode`

Any other key in the `$details` array is silently stripped.

### Query Methods

- `getEventsForUser($userId, $limit)` — User-scoped timeline
- `getRecentEvents($limit, $eventFilter)` — Global feed with optional filter
- `purgeOldEntries($daysToKeep)` — Retention cleanup

## Events Logged

| Event | When | Source |
|-------|------|--------|
| `password_changed` | After successful password save | PasswordPolicy.php EVENT_AFTER_SAVE |
| `password_reset_forced` | After force reset | RetentionService (future) |
| `hibp_breach_detected` | Password found in HIBP | PwnedValidator |
| `hibp_check_failed` | HIBP API unreachable | PwnedValidator |
| `account_locked` | Craft locks user after failed attempts | Users::EVENT_AFTER_LOCK_USER |
| `account_unlocked` | Admin unlocks user | Users::EVENT_AFTER_UNLOCK_USER |

## PwnedValidator Updates

- Now returns `null` on API failure (distinct from `false` = not breached)
- Supports fail-open (default) and fail-closed modes via `pwnedFailMode` setting
- Logs `hibp_breach_detected` and `hibp_check_failed` to audit log
- `#[SensitiveParameter]` added to `pwned()` method

## AuditController (Console)

- `password-policy/audit/purge --days=365` — Purge old entries
- `password-policy/audit/export --format=csv --days=90` — Export to stdout
- `--include-user-details` flag resolves user emails for export

## GDPR Notes

- IP addresses stored as SHA-256 hashes only
- User identifier uses HMAC-SHA-256 (key can be destroyed)
- User deletion: SET NULL preserves anonymous audit records
- Configurable retention period (default 365 days)
