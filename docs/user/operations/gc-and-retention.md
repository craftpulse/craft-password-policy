# Garbage Collection and Retention

Password Policy keeps six retention-managed datasets: password history, notification log, audit log, alert cooldowns, known devices, and API tokens. This page covers how those tables are pruned, what the recommended production setup is, and which retention windows are configurable.

For production cron recipes including the audit verifier, see [Cron setup](./cron-setup.md).

## What gets pruned

| Table | Retention setting | Default | Edition | Strategy |
|---|---|---|---|---|
| `passwordpolicy_password_history` | `passwordHistoryCount` + `passwordHistoryExpiryDays` | 5 rows × 365 days | All editions | Keep the latest N rows per user. Delete rows beyond N that are older than the day window. Per-group `passwordHistoryCount` overrides require Pro. |
| `passwordpolicy_notification_log` | `notificationLogRetentionDays` | 30 days | Pro | Hard-delete rows older than the window. |
| `passwordpolicy_alert_cooldowns` | none (derived) | Longest configured cooldown, 7-day floor | All editions | Hard-delete rows older than the derived window. |
| `passwordpolicy_audit_log` | `auditLogRetentionDays` | 365 days | Enterprise (capture is universal; purge runs on every edition) | Hard-delete rows older than the window via `craft_elements` DELETE + FK CASCADE. |
| `passwordpolicy_known_devices` | `deviceRetentionDays` | 180 days | All editions (capture is universal) | Hard-delete rows whose `lastSeenAt` is older than the window. |
| `passwordpolicy_api_tokens` | none (per-token `expiresAt`) | no expiry unless set | Enterprise | Hard-delete rows whose `expiresAt` has passed. Tokens issued without an expiry are never purged. |

The audit log retention default of 365 days satisfies PCI DSS v4.0.1 §10.5.1's "at least 12 months" requirement exactly.

> [!TIP]
> **Retention is a hard delete on every table**
>
> No soft-delete via `dateDeleted`. Compliance frameworks require retention windows actually remove the data, not just hide it. The verifier CLI tolerates this: it walks the surviving rows and verifies the chain among them. See [Audit verifier → Retention-purge tolerance](../features/audit-verifier.md#retention-purge-tolerance).

## Two mechanisms

The plugin offers two retention mechanisms: the cron is **the** recommended production setup; the GC hook is a best-effort fallback.

### Console command (`password-policy/gc/run`): recommended

Deterministic cleanup. Schedule via cron for guaranteed retention compliance:

```cron
# Daily at 02:00 local time
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run
```

The command reports per-table purge counts on stdout, pipe to a log file for auditable retention records:

```cron
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run >> /var/log/pp-gc.log 2>&1
```

> [!WARNING]
> **Retention is not automatic**
>
> The cron is the enforcement mechanism. Without it, the retention windows you configure are advisory: rows stay in the table past their window until something runs the purge. Treat the cron as part of the production install, not as an optional extra.

### Craft GC hook (`Gc::EVENT_RUN`): fallback

The plugin attaches to Craft's own GC event so a `./craft gc` invocation (or Craft's probabilistic-trigger GC) also runs the plugin's retention. Useful for dev environments + emergency cleanup; not a substitute for the cron in production.

The hook fires:

- When Craft's own GC trigger fires (probabilistic, configurable via `gcProbability` in `config/general.php`).
- When an operator runs `./craft gc` explicitly.

On low-traffic sites (exactly the kind that run compliance-grade password policies) the probabilistic GC may fire weeks apart. Retention periods become approximate when this is the only mechanism. Always configure the cron.

## Configuration

Retention windows are surfaced in the CP under **Settings → Password Policy → Retention** and **→ Audit** (Enterprise). The Retention page is universal across editions; `notificationLogRetentionDays` is the only Pro-gated field on it.

| Setting | Type | Default | Edition |
|---|---|---|---|
| `passwordHistoryCount` | int | `0` (disabled) | All editions |
| `passwordHistoryExpiryDays` | int | `365` | All editions |
| `notificationLogRetentionDays` | int | `30` | Pro |
| `deviceRetentionDays` | int | `180` | All editions |
| `auditLogRetentionDays` | int | `365` | Enterprise |

Every setting can be overridden via `config/password-policy.php` with `App::env()` for env-var indirection:

```php
<?php

use craft\helpers\App;

return [
    'auditLogRetentionDays' => (int) App::env('PP_AUDIT_LOG_RETENTION_DAYS') ?: 365,
];
```

## Configuring longer retention

For longer-than-default retention (e.g. a 7-year audit trail for finance-sector compliance):

1. Bump `auditLogRetentionDays` to your target (e.g. `2555` for 7 years).
2. Provision additional database storage: at 100k events/year on a busy site, 7 years is ~700k rows.
3. Verify the chain stays performant: `./craft password-policy/audit/verify --json` on the full chain at month-end as a benchmark.

For installs needing longer retention than the database can comfortably hold, combine a shorter live retention with periodic archival via [Audit export](../features/audit-export.md):

- Keep 90 days live in the DB (smaller `auditLogRetentionDays`).
- Export monthly JSONL snapshots to S3 with Object Lock for long-term retention.
- Run the verifier against the live DB monthly + verify archived JSONL on demand using the plugin source from GitHub.

## Compliance-grade retention proof

Auditors asking "show me that audit data is actually deleted after 365 days":

1. Show the cron entry running `password-policy/gc/run` nightly.
2. Show `/var/log/pp-gc.log` (or your equivalent) with daily per-table purge counts.
3. Show the compliance dashboard's **Retention** section with the projected next-prune date.
4. Show the `auditLogRetentionDays` value in project config.

Combined, this demonstrates a documented + enforced retention policy: the standard ask under PCI DSS §10.5.1, GDPR Art. 5(1)(e), ISO 27002:2022 A.5.33.

## Migration impact

When the cron runs after a long pause (e.g. you set up the cron weeks after the upgrade), the first run may delete a large batch of rows that exceeded retention while no cron was active. This is expected. Subsequent runs are small deltas.

There is no dry-run mode. To see the size of that first delete before you commit to it, count the rows the windows will catch:

```sql
SELECT COUNT(*) FROM passwordpolicy_audit_log
WHERE dateCreated < NOW() - INTERVAL 365 DAY;
```

Substitute each table and its configured window. Then run the command once by hand and read the per-table purge counts it prints, before you put it on a schedule.

## See also

- [Cron setup](./cron-setup.md): full production cron recipes including audit verification.
- [Audit logging → Retention](../features/audit-logging.md#retention): audit-log-specific retention details.
- [Notifications → Retention](../features/notifications.md#retention): notification-log retention details.
- [Compliance frameworks](./compliance-frameworks.md): per-framework retention clauses.
- [Audit export](../features/audit-export.md): archive workflows for longer-than-DB retention.
