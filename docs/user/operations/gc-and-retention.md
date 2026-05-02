# Garbage Collection and Retention

Password Policy stores three retention-managed datasets — password history (Pro), notification log (Pro+), audit log (Enterprise). This page covers how those tables are pruned, what the recommended production setup is, and which retention windows are configurable.

Related pages:
- [Notifications](../features/notifications.md) — what writes to the notification log in the first place
- [Audit logging](../features/audit-logging.md) — Enterprise audit-log table covered by `auditLogRetentionDays`

<!-- TODO: P1.8 deployment docs land here -->

## Two mechanisms — use both

### Console command (`password-policy/gc/run`) — recommended for production

Deterministic cleanup. Schedule via cron for guaranteed retention compliance:

```
# Daily at 2am
0 2 * * * /usr/bin/env php /path/to/craft password-policy/gc/run
```

Reports per-table purge counts and respects all configured retention periods. Same logic as the GC hook below, but runs on a predictable schedule.

**Compliance note:** If your DPO or auditor requires exact retention periods (e.g., "audit data deleted after exactly 365 days"), configure the cron job. The GC hook alone cannot guarantee timing on low-traffic sites.

### GC hook (`Gc::EVENT_RUN`) — best-effort fallback

Craft's GC runs probabilistically (1 in 100,000 requests by default). On low-traffic internal sites — exactly the kind that run enterprise password policies — this may fire weeks apart. Retention periods become approximate when this is the only mechanism.

## What gets purged

Both mechanisms run the same logic:

- **password_history** — respects count floor per user, only deletes overflow entries beyond TTL — Pro
- **notification_log** — `notificationLogRetentionDays` (default 30) — Pro+
- **audit_log** — `auditLogRetentionDays` (default 365) — Enterprise

Device tracking (`known_devices`) purge will be added in Phase 10.

## Configuration

Retention windows are surfaced in the CP under Settings → Retention. The two non-Lite controls are:

- `notificationLogRetentionDays` — Pro. How long dedup rows in `passwordpolicy_notification_log` are kept before purge.
- `auditLogRetentionDays` — Enterprise. How long audit-log rows are kept before purge.

Both can be overridden via project config and resolved through environment variables (`$PP_NOTIFICATION_LOG_RETENTION_DAYS` style references).
