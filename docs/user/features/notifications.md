# Notifications

Pro and Enterprise editions ship the notification infrastructure for password-related emails — expiry reminders, breach alerts, admin notifications — backed by a CP template editor and a Craft queue job.

Related pages:
- [Operations: garbage collection + retention](../operations/gc-and-retention.md) — `password-policy/gc/run` cron, retention windows, notification log purge
- [Reference: AJAX `/validate` endpoint](../reference/ajax-validate.md) — front-end / partner integrations

## NotificationService

Three notification methods, all using Craft's mailer with dedup tracking:

- `sendPasswordExpiryReminder(User, int $daysRemaining)` — Pro+. Deduped per user within the reminder window.
- `sendNewDeviceAlert(User, string $deviceLabel, string $maskedIp)` — Enterprise. Logs to notification_log.
- `sendAdminSecurityAlert(string $event, array $context)` — Enterprise. Deduped within 5 minutes per event type.

Old log purging is handled by `RetentionService::purgeNotificationLog()` — see [operations: gc-and-retention](../operations/gc-and-retention.md).

## Notification Log Table

`passwordpolicy_notification_log` tracks sent notifications for dedup:
- `userId`, `notificationType`, `sentAt`
- CASCADE on user delete
- Created by Install.php for fresh installs
- Upgraded by migration `m250419_100000_AddNotificationLogTable` for existing installs

## Twig Variables

Expanded `PasswordPolicyVariable` exposes status accessors useful inside notification email templates:

- `daysUntilExpiry()` — Days until password expires (null if no expiration)
- `isExpired()` — Whether password is past expiration
- `isExpiring(int $days = 14)` — Whether password expires within window
- `passwordStatus()` — One of: current, expiring, expired, reset_required, never_changed, unknown
- `lastPasswordChange()` — DateTime of last change
- `activeSessionCount()` — Number of active sessions (from Table::SESSIONS)
