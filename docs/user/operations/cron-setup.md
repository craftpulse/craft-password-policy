# Cron Setup

Password Policy ships six cron-friendly console commands. This page covers the recommended production cron recipes, what each command does, and how to wire them into your existing scheduler, system cron, Laravel-style scheduler, Kubernetes CronJobs, or whatever you already use.

For the full option reference on every command, see [Console commands](../reference/console-commands.md).

## Recommended production cron

Every edition:

```cron
# Retention + GC nightly at 02:00 local time
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run

# Expiry reminder emails nightly at 06:00 local time
0 6 * * * cd /path/to/project && ./craft password-policy/notification/send-expiry-reminders
```

On Pro, if you have turned on dormant-account handling:

```cron
# Dormant-account scan weekly, Sundays at 04:00 local time
0 4 * * 0 cd /path/to/project && ./craft password-policy/inactive/scan
```

On Enterprise, add the audit-chain verifier, plus the forward sweeps for whichever outbound delivery you have configured:

```cron
# Audit-chain verification nightly at 03:00 local time
0 3 * * * cd /path/to/project && ./craft password-policy/audit/verify --json

# SIEM forward sweep every five minutes
*/5 * * * * cd /path/to/project && ./craft password-policy/siem/run

# Webhook delivery sweep every five minutes
*/5 * * * * cd /path/to/project && ./craft password-policy/webhook/run
```

Adjust the times for your timezone and infrastructure preferences. The order is: retention first (small DB cleanup), reminders later (user-facing email), verifier last (read-only check over the day's writes). The two sweeps run all day on a short interval, because their job is to keep the outbound backlog near zero rather than to do a once-daily pass.

Skip the sweep you have no forwarders or endpoints for. Both commands exit zero and enqueue nothing when nothing is configured, so leaving them scheduled ahead of time is harmless, but there is no reason to schedule delivery you have not set up.

> [!WARNING]
> **The verifier has no date filter**
>
> `audit/verify` takes `--from` and `--to` as row **ids**, not dates. Passing a date (`--from=$(date +%F)`) is read as an id far beyond anything your table holds, so the verifier walks an empty range and cheerfully reports a clean pass over zero rows. Run it with no range, as above. That is also the only mode that tolerates rows removed by the retention purge.

The full-chain walk is the correct nightly recipe. If your chain grows large enough that a nightly full walk stops fitting in your maintenance window, narrow it by row id (capture the current maximum id, verify from there next run) rather than by date, and keep a monthly full walk for the evidence package.

## Why each command needs cron

### `password-policy/gc/run`: retention enforcement

Without this cron, retention windows are advisory only. The plugin captures rows on every event but doesn't auto-prune, that's a separate cron-driven cleanup step. Compliance frameworks generally treat retention as a documented + enforced policy; running the GC nightly produces the actual enforcement.

Tables pruned:

- `passwordpolicy_password_history`: beyond `passwordHistoryCount` per user AND older than `passwordHistoryExpiryDays`.
- `passwordpolicy_notification_log`: older than `notificationLogRetentionDays`.
- `passwordpolicy_alert_cooldowns`: older than the longest configured cooldown window, with a 7-day floor. There is no separate retention setting for this table.
- `passwordpolicy_audit_log`: older than `auditLogRetentionDays` (default 365 days).
- `passwordpolicy_known_devices`: older than `deviceRetentionDays` (default 180 days).
- `passwordpolicy_api_tokens`: rows whose `expiresAt` has passed.

The command reports per-table purge counts on stdout, pipe to a log file if you want auditable retention records:

```cron
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run >> /var/log/pp-gc.log 2>&1
```

See [GC and retention](./gc-and-retention.md) for the per-table retention configuration.

### `password-policy/notification/send-expiry-reminders`: proactive reminders

Sends reminder emails to users whose passwords expire within the configured window (`expiryReminderDays`, default 14). Without this cron, expiry reminders never fire, passwords expire silently, and users see the "your password has expired" prompt only on their next login attempt.

The command enqueues `SendPasswordExpiryRemindersJob` (a `BaseBatchedJob`) which recomputes its recipient set per batch for natural retry idempotency, 100 users at a time. Runs on every edition since 5.2.0.

### `password-policy/inactive/scan`: dormant accounts

Pro. Enqueues the scan that finds accounts with no sign-in inside `inactiveThresholdDays` and applies the configured `inactiveAction` to each. Nothing happens unless you both hold the Pro edition and turn on `inactiveAccountsEnabled`; the command exits non-zero otherwise rather than enqueuing a job that would do nothing.

Weekly is usually the right cadence: dormancy is measured in months, so a daily scan buys nothing and, under the `suspend` action, gives you a daily opportunity to be surprised. Run it in `report` mode first and read the list before you switch the setting to `suspend`.

See [Dormant accounts](../features/dormant-accounts.md).

### `password-policy/audit/verify`: chain check

Enterprise. Walks the audit chain and recomputes each row's `rowHash`, comparing against the stored value. A non-zero exit code means the chain broke: an alertable event.

Exit `1` is a chain break, exit `2` is an unreadable row (schema drift, malformed JSON, database failure). Route them differently: the first is a security page, the second is an ops page.

See [Audit verifier](../features/audit-verifier.md) for the verifier's output format + JSON shape.

### `password-policy/siem/run`: audit forwarding

Enterprise. Enqueues the batched job that forwards audit rows to every active SIEM forwarder, stamping each row's `forwardedAt` as a forwarder accepts it.

Nothing enqueues that job for you. Without this cron the forwarders you configured are inert: every row keeps an empty `forwardedAt`, the pending count on the forwarder index climbs, and nothing reaches your SIEM. It fails silently, which is the worst way for a compliance feature to fail, so treat the cron as part of setting up a forwarder rather than as an optimisation.

Two things have to be running, not one:

1. This command, which enqueues the sweep.
2. A queue runner, which executes it. See the queue note in [SIEM forwarders](../features/siem-forwarders.md).

Five minutes is a reasonable interval. Shorten it if your SIEM ingestion window is tight; the command is cheap and enqueues nothing when no forwarder is active.

### `password-policy/webhook/run`: webhook delivery

Enterprise. Enqueues the batched job that delivers audit rows to every active webhook endpoint, advancing each endpoint's own `lastDeliveredRowId` cursor.

Same shape as the SIEM sweep, and the same failure mode: without the cron, no webhook is ever delivered. Consumers see nothing, and there is no error anywhere, because nothing was ever attempted.

Confirm it is working with `./craft password-policy/webhook/list` and watch the `CURSOR` column advance. A cursor stuck at `-` on an endpoint that should be receiving events means either this cron or your queue runner is not running.

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

```shell
cd /home/forge/yoursite.com && /usr/bin/php craft password-policy/gc/run
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

Replicate the pattern for the other commands you schedule. Use Kubernetes secrets to inject `CRAFT_AUDIT_PII_KEY` and other env vars.

### Laravel-style scheduler (if your Craft project also uses Laravel for something else)

If you're running Laravel alongside Craft for some reason (e.g. an admin SPA), the Laravel scheduler can drive the cron via `php artisan schedule:run` once a minute:

```php
// app/Console/Kernel.php
$schedule->exec('cd /path/to/project && ./craft password-policy/gc/run')->dailyAt('02:00');
$schedule->exec('cd /path/to/project && ./craft password-policy/notification/send-expiry-reminders')->dailyAt('06:00');
$schedule->exec('cd /path/to/project && ./craft password-policy/audit/verify --json')->dailyAt('03:00');
$schedule->exec('cd /path/to/project && ./craft password-policy/siem/run')->everyFiveMinutes();
$schedule->exec('cd /path/to/project && ./craft password-policy/webhook/run')->everyFiveMinutes();
```

## Monitoring

The verifier command's non-zero exit code is an alertable event. Pipe to your log aggregator:

```cron
0 3 * * * cd /path/to/project && ./craft password-policy/audit/verify --json >> /var/log/pp-audit-verify.log 2>&1
```

Forward `/var/log/pp-audit-verify.log` to your monitoring stack. A non-zero exit code is **the** signal: the only normal day-to-day reason for non-zero is chain tampering or a disk error.

For the GC command, monitoring is less critical, non-zero usually means a transient DB lock or a misconfigured retention setting. The command logs to `password-policy-*.log` on its own; alerting on that file's content is sufficient.

For expiry reminders, the queue's own observability (Craft's Utilities → Queue Manager, or whatever queue runner you use) covers the operational visibility.

For the two forward sweeps, exit codes are a weak signal by design: the command's job is only to enqueue, so a zero exit means "queued", not "delivered". Monitor the backlog instead. Both the SIEM forwarders index and the webhooks index warn when the oldest row waiting for a first delivery attempt is more than two hours old, which is what a missing sweep entry or a stopped queue runner looks like from the database. `./craft password-policy/webhook/list` reports each endpoint's cursor, and the compliance dashboard surfaces pending SIEM forwards. A backlog that grows monotonically means the sweep cron or the queue runner has stopped, not that a forwarder is refusing rows: a forwarder that refuses rows records failures and trips its circuit, both of which show on the index.

## Verifying the cron is running

There is no command that reports "when did this last run". Redirect each command's output to a log file and check the file instead. That is also what an auditor will ask for, so it is worth doing on the first day rather than the day before the audit:

```cron
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run >> /var/log/pp-gc.log 2>&1
0 6 * * * cd /path/to/project && ./craft password-policy/notification/send-expiry-reminders >> /var/log/pp-reminders.log 2>&1
0 3 * * * cd /path/to/project && ./craft password-policy/audit/verify --json >> /var/log/pp-audit-verify.log 2>&1
```

Then check the tail of each file. If the newest entry is more than 25 hours old, your cron is not firing.

Two control panel surfaces corroborate this from the other direction:

- **Utilities → Compliance dashboard** (Enterprise) shows the audit chain status and a projected next prune date under **Retention**. A projected prune date in the past means the GC cron is not running.
- **Utilities → Queue Manager** shows whether the reminder, scan, and forward-sweep jobs are being enqueued and completing.

The sweeps are worth a second check, because they are the two whose failure produces no error anywhere:

```cron
*/5 * * * * cd /path/to/project && ./craft password-policy/siem/run >> /var/log/pp-siem.log 2>&1
*/5 * * * * cd /path/to/project && ./craft password-policy/webhook/run >> /var/log/pp-webhook.log 2>&1
```

A log full of `No active SIEM forwarders. Nothing enqueued.` means the cron is firing but nothing is configured to receive. A log with no recent lines at all means the cron is not firing.

## Crontab vs the GC hook

In addition to the console commands above, the plugin attaches to Craft's `Gc::EVENT_RUN` event: the same hook Craft uses for its own user/session/entry cleanup. This means a Craft-driven GC pass (e.g. via `./craft gc`) also runs the plugin's retention logic.

That's a backup mechanism, not a primary one. **For production, use the explicit cron**:

- The GC hook fires only when Craft's own GC fires. Low-traffic sites can go days without one.
- The hook runs on every Craft GC trigger: including ad-hoc CLI runs that the operator might not intend to drive retention.
- The cron gives you a predictable retention schedule that auditors can verify against.

> [!WARNING]
> **Retention is not automatic**
>
> The cron is the enforcement mechanism, not the GC hook. Without the cron, the retention windows you configure are advisory: rows stay in the table past their window until something runs the purge.

## See also

- [GC and retention](./gc-and-retention.md): per-table retention configuration.
- [Audit verifier](../features/audit-verifier.md): verifier output + JSON shape.
- [Notifications](../features/notifications.md): expiry reminder template + tokens.
- [SIEM forwarders](../features/siem-forwarders.md): forwarder configuration + circuit breaker.
- [Webhooks](../features/webhooks.md): endpoint configuration + signature verification.
- [Compliance frameworks](./compliance-frameworks.md): retention requirements per framework.
