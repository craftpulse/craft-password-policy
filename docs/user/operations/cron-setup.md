# Cron Setup

Password Policy ships three cron-friendly console commands. This page covers the recommended production cron recipes, what each command does, and how to wire them into your existing scheduler, system cron, Laravel-style scheduler, Kubernetes CronJobs, or whatever you already use.

## Recommended production cron

For a typical Pro install:

```cron
# Retention + GC nightly at 02:00 local time
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run

# Expiry reminder emails nightly at 06:00 local time
0 6 * * * cd /path/to/project && ./craft password-policy/notification/send-expiry-reminders
```

For an Enterprise install, add:

```cron
# Daily audit-chain verification at 03:00 local time
0 3 * * * cd /path/to/project && ./craft password-policy/audit/verify --from=$(date -d yesterday +%Y-%m-%d) --json

# Monthly full-chain verification on the 1st at 02:00 local time
0 2 1 * * cd /path/to/project && ./craft password-policy/audit/verify --json
```

Adjust the times for your timezone and infrastructure preferences. The order is: retention first (small DB cleanup), reminders later (user-facing email), verifier last (read-only check of yesterday's writes).

## Why each command needs cron

### `password-policy/gc/run`: retention enforcement

Without this cron, retention windows are advisory only. The plugin captures rows on every event but doesn't auto-prune, that's a separate cron-driven cleanup step. Compliance frameworks generally treat retention as a documented + enforced policy; running the GC nightly produces the actual enforcement.

Tables pruned:

- `passwordpolicy_password_history`: beyond `passwordHistoryCount` per user AND older than `passwordHistoryExpiryDays`.
- `passwordpolicy_notification_log`: older than `notificationLogRetentionDays`.
- `passwordpolicy_alert_cooldowns`: older than `alertCooldownRetentionDays` (default 30 days).
- `passwordpolicy_audit_log`: older than `auditLogRetentionDays` (default 365 days).

The command reports per-table purge counts on stdout, pipe to a log file if you want auditable retention records:

```cron
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run >> /var/log/pp-gc.log 2>&1
```

See [GC and retention](./gc-and-retention.md) for the per-table retention configuration.

### `password-policy/notification/send-expiry-reminders`: proactive reminders

Sends reminder emails to users whose passwords expire within the configured window (`expiryReminderDays`, default 14). Without this cron, expiry reminders never fire, passwords expire silently, and users see the "your password has expired" prompt only on their next login attempt.

The command enqueues `SendPasswordExpiryRemindersJob` (a `BaseBatchedJob`) which recomputes its recipient set per batch for natural retry idempotency. Runs on every edition since 5.2.0.

For installs with very large user bases (>100k users with expiry enabled), tune the batch size via the `expiryReminderBatchSize` setting.

### `password-policy/audit/verify --from=yesterday`: daily chain check

Enterprise-only. Walks yesterday's audit rows and recomputes each row's `rowHash`, comparing against the stored value. Non-zero exit code means the chain broke somewhere in yesterday's window: an alertable event.

Daily incremental verification + monthly full-chain verification gives you:

- **Daily detection**: tampering visible within 24 hours.
- **Monthly attestation**: periodic proof-of-integrity for the entire chain, useful for evidence packages.

See [Audit verifier](../features/audit-verifier.md) for the verifier's output format + JSON shape.

## Where to put the cron

### Linux system cron

Edit your crontab:

```bash
crontab -e
```

Or as the user that owns the Craft application:

```bash
sudo crontab -u www-data -e
```

Add the entries above, save. Verify with `crontab -l`.

### DDEV (local development)

For DDEV-based local development, use a `pre-import` or `post-start` hook in `.ddev/config.yaml`:

```yaml
hooks:
  post-start:
    - exec: "echo '0 2 * * * /var/www/html && /var/www/html/craft password-policy/gc/run' | crontab -"
```

Most DDEV users don't need cron locally, exercise the commands manually when testing.

### Forge / Ploi / Cleavr

These platforms ship cron UIs. Add a new cron entry with the command:

```
cd /home/forge/yoursite.com && /usr/bin/php artisan-craft password-policy/gc/run
```

Adjust the binary name and path to match your platform's deployment shape.

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: pp-gc
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: craft
              image: <your-craft-image>
              command:
                - /var/www/html/craft
                - password-policy/gc/run
          restartPolicy: OnFailure
```

Replicate the pattern for the other two commands. Use Kubernetes secrets to inject `CRAFT_AUDIT_PII_KEY` and other env vars.

### Laravel-style scheduler (if your Craft project also uses Laravel for something else)

If you're running Laravel alongside Craft for some reason (e.g. an admin SPA), the Laravel scheduler can drive the cron via `php artisan schedule:run` once a minute:

```php
// app/Console/Kernel.php
$schedule->exec('cd /path/to/project && ./craft password-policy/gc/run')->dailyAt('02:00');
$schedule->exec('cd /path/to/project && ./craft password-policy/notification/send-expiry-reminders')->dailyAt('06:00');
$schedule->exec('cd /path/to/project && ./craft password-policy/audit/verify --json --from='.now()->subDay()->format('Y-m-d'))->dailyAt('03:00');
```

## Monitoring

The verifier command's non-zero exit code is an alertable event. Pipe to your log aggregator:

```cron
0 3 * * * cd /path/to/project && ./craft password-policy/audit/verify --json --from=$(date -d yesterday +%Y-%m-%d) >> /var/log/pp-audit-verify.log 2>&1
```

Forward `/var/log/pp-audit-verify.log` to your monitoring stack. A non-zero exit code is **the** signal: the only normal day-to-day reason for non-zero is chain tampering or a disk error.

For the GC command, monitoring is less critical, non-zero usually means a transient DB lock or a misconfigured retention setting. The command logs to `password-policy-*.log` on its own; alerting on that file's content is sufficient.

For expiry reminders, the queue's own observability (Craft's Utilities → Queue Manager, or whatever queue runner you use) covers the operational visibility.

## Verifying the cron is running

After setting up cron, verify it fires on schedule:

```bash
# GC last-run timestamp (lives in cache; cron writes it)
./craft password-policy/gc/last-run

# Most recent verifier run
./craft password-policy/audit/last-verify

# Most recent expiry-reminder batch
./craft password-policy/notification/last-reminder-batch
```

These commands surface metadata that the compliance dashboard's **Retention** and **Audit chain status** sections also read. If the timestamps drift more than 25 hours from "now," your cron isn't firing.

## Crontab vs the GC hook

In addition to the console commands above, the plugin attaches to Craft's `Gc::EVENT_RUN` event: the same hook Craft uses for its own user/session/entry cleanup. This means a Craft-driven GC pass (e.g. via `./craft gc`) also runs the plugin's retention logic.

That's a backup mechanism, not a primary one. **For production, use the explicit cron**:

- The GC hook fires only when Craft's own GC fires. Low-traffic sites can go days without one.
- The hook runs on every Craft GC trigger: including ad-hoc CLI runs that the operator might not intend to drive retention.
- The cron gives you a predictable retention schedule that auditors can verify against.

> ::: warning Don't say "pruning is automatic"
> The framing "pruning is automatic" implies operator-free retention. The reality is: the cron is the recommended production setup. Without the cron, retention windows are advisory. Documentation, marketing copy, and compliance attestations should describe the cron as the enforcement mechanism, not the GC hook.
> :::

## See also

- [GC and retention](./gc-and-retention.md): per-table retention configuration.
- [Audit verifier](../features/audit-verifier.md): verifier output + JSON shape.
- [Notifications](../features/notifications.md): expiry reminder template + tokens.
- [Compliance frameworks](./compliance-frameworks.md): retention requirements per framework.
