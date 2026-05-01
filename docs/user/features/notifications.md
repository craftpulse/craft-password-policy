# Phase 9 — Notification Infrastructure + GC Hook + Validation Controller

## Overview

Phase 9 adds the notification email system, Craft GC hook for automatic data purge, real-time AJAX validation endpoint, and expanded Twig variables.

## NotificationService

Three notification methods, all using Craft's mailer with dedup tracking:

- `sendPasswordExpiryReminder(User, int $daysRemaining)` — Pro+. Deduped per user within the reminder window.
- `sendNewDeviceAlert(User, string $deviceLabel, string $maskedIp)` — Enterprise. Logs to notification_log.
- `sendAdminSecurityAlert(string $event, array $context)` — Enterprise. Deduped within 5 minutes per event type.
- `pruneOldEntries(int $daysToKeep)` — Purges old notification log entries.

## Notification Log Table

`passwordpolicy_notification_log` tracks sent notifications for dedup:
- `userId`, `notificationType`, `sentAt`
- CASCADE on user delete
- Added to Install.php for fresh installs
- Upgrade migration: `m250419_100000_AddNotificationLogTable`

## Data Retention

Two mechanisms, use both:

### GC Hook (`Gc::EVENT_RUN`) — Best-effort fallback

Craft's GC runs probabilistically (1 in 100,000 requests by default). On low-traffic internal sites — exactly the kind that run enterprise password policies — this may fire weeks apart. Retention periods become approximate.

Purges:
- **password_history** — respects count floor per user, only deletes overflow entries beyond TTL — Pro
- **notification_log** — `notificationLogRetentionDays` (default 30) — Pro+
- **audit_log** — `auditLogRetentionDays` (default 365) — Enterprise

### Console Command (`password-policy/gc/run`) — Recommended for production

Deterministic cleanup. Schedule via cron for guaranteed retention compliance:

```
# Daily at 2am
0 2 * * * /usr/bin/env php /path/to/craft password-policy/gc/run
```

Reports per-table purge counts and respects all configured retention periods. Same logic as the GC hook but runs on a predictable schedule.

**Compliance note:** If your DPO or auditor requires exact retention periods (e.g., "audit data deleted after exactly 365 days"), configure the cron job. The GC hook alone cannot guarantee timing on low-traffic sites.

Device tracking (known_devices) purge will be added in Phase 10.

## ValidationController (AJAX)

`POST password-policy/validate` — Returns per-rule pass/fail JSON:

```json
{
  "isValid": false,
  "rules": [
    { "key": "minLength", "pass": true, "message": "At least 8 characters" },
    { "key": "cases", "pass": false, "message": "Upper and lowercase letters" },
    { "key": "pwned", "pass": null, "message": "Not found in breach database" }
  ]
}
```

- `$allowAnonymous = ['validate']` — works for front-end registration forms
- Accepts `password` (required), `username`/`email` (optional for contextual validation)
- `null` pass value = HIBP still checking (async-friendly)
- Each validator invoked individually for per-rule granularity

## Twig Variables

Expanded `PasswordPolicyVariable` with:
- `daysUntilExpiry()` — Days until password expires (null if no expiration)
- `isExpired()` — Whether password is past expiration
- `isExpiring(int $days = 14)` — Whether password expires within window
- `passwordStatus()` — One of: current, expiring, expired, reset_required, never_changed, unknown
- `lastPasswordChange()` — DateTime of last change
- `activeSessionCount()` — Number of active sessions (from Table::SESSIONS)
