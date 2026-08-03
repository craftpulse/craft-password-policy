# Console Commands

Every console command the plugin ships. Run them from your Craft project root.

Commands are shown with `./craft`. If your project runs in DDEV, substitute `ddev craft`:

```shell
./craft password-policy/gc/run
```

```shell
ddev craft password-policy/gc/run
```

`./craft help password-policy` lists the same set at any time, and
`./craft help password-policy/<command>` prints the per-command options.

Five commands are the ones you schedule. Everything else is run by hand.

| Command | Purpose |
|---|---|
| [`gc/run`](#gcrun) | Enforce every retention window. |
| [`notification/send-expiry-reminders`](#notificationsend-expiry-reminders) | Send expiry reminder emails. |
| [`inactive/scan`](#inactivescan) | Act on dormant accounts. |
| [`siem/run`](#siemrun) | Forward audit rows to your SIEM forwarders. |
| [`webhook/run`](#webhookrun) | Deliver audit rows to your webhook endpoints. |

See [Cron setup](../operations/cron-setup.md) for the schedules.

## Retention and garbage collection

### `gc/run`

Prunes every retention-managed table in one pass: password history, notification log, audit log, alert cooldowns, known devices, and expired API tokens. Each table respects its own configured window.

```shell
./craft password-policy/gc/run
```

Takes no options. Prints a per-table purge count to stdout, which is what you redirect into a log file when an auditor wants evidence that retention runs.

See [GC and retention](../operations/gc-and-retention.md).

### `retention/force-reset-passwords`

Flags every account whose password is already past the configured expiry window, so those users must set a new password on their next sign-in. Runs on every edition. Admin accounts are skipped.

Requires the `retentionUtilities` setting to be on; with it off the command writes to stderr and exits non-zero. The console path does not check permissions, because shell access is already privileged. The equivalent control panel action, on the Password Retention utility, is gated by `pp:force-reset-passwords`.

```shell
./craft password-policy/retention/force-reset-passwords
```

| Option | Description |
|---|---|
| `--queue` | Push the work to the queue instead of running it synchronously. |
| `--verbose` | Print per-user output rather than a summary. |

This is the mass path. It never targets a named account. For that, use the per-user actions described in [Force reset](../features/force-reset.md).

See [Force reset](../features/force-reset.md).

## Notifications

### `notification/send-expiry-reminders`

Enqueues the batched job that emails users approaching their expiry window, using the `expiry-reminder` template.

```shell
./craft password-policy/notification/send-expiry-reminders
```

| Option | Description |
|---|---|
| `--user` | Target a single user ID instead of every expiring user. |

Use `--user` to check the template end to end against one account before scheduling the command:

```shell
./craft password-policy/notification/send-expiry-reminders --user=42
```

See [Notifications](../features/notifications.md).

## Dormant accounts

### `inactive/scan`

Enqueues the dormant-account scan. Requires the Pro edition and the `inactiveAccountsEnabled` setting; on a lower edition or with the setting off, the command writes to stderr and exits non-zero rather than silently enqueuing a job that would do nothing.

```shell
./craft password-policy/inactive/scan
```

| Option | Description |
|---|---|
| `--threshold` | Override the configured `inactiveThresholdDays` for this run. |
| `--mode` | Override the configured `inactiveAction`: `report`, `notify`, or `suspend`. |

The overrides exist so you can rehearse a destructive configuration without committing to it. Run the scan in `report` mode against your intended threshold first, read the resulting list, and only then switch the setting to `suspend`:

```shell
./craft password-policy/inactive/scan --threshold=90 --mode=report
```

The flag is `--mode` rather than `--action` because `action` is already taken by Yii's own controller property.

See [Dormant accounts](../features/dormant-accounts.md).

## Blocklist

### `blocklist/update`

Re-seeds the bundled common-password list from the plugin's data file. Run it after a plugin update, when the bundled list may have changed. Existing custom words are untouched.

```shell
./craft password-policy/blocklist/update
```

Takes no options.

### `blocklist/import`

Imports custom blocked words from a text file, one word per line. Duplicates are skipped rather than erroring. Requires the Pro edition.

```shell
./craft password-policy/blocklist/import --file=path/to/words.txt
```

| Option | Description |
|---|---|
| `--file` | Path to the word list. Required. |

### `blocklist/stats`

Prints blocklist row counts broken down by source, so you can confirm the bundled list actually seeded.

```shell
./craft password-policy/blocklist/stats
```

Takes no options.

See [Blocklist](../features/blocklist.md).

## Audit log

`verify` and `schema` run on every edition: they are the open verification surface, and an auditor needs to be able to run them from a fresh checkout. The commands that expose audit *data* (`export`) require the Enterprise edition.

### `audit/verify`

Walks the audit log's hash chain and reports whether it is intact.

```shell
./craft password-policy/audit/verify
```

| Option | Description |
|---|---|
| `--from` | Start row id, inclusive. |
| `--to` | End row id, inclusive. |
| `--json` | Emit JSON Lines (one row per line plus a summary) instead of human-readable text. |
| `--quiet` | Suppress the per-row OK lines on a clean pass, leaving only the summary. |

> [!WARNING]
> **`--from` and `--to` are row ids, not dates**
>
> `--from=2026-01-01` does not mean "since January". It is read as a row id, and the leading `2026` makes it an id far beyond anything your table holds, so the verifier walks an empty range and reports a clean pass over nothing. Omit both options to verify the whole chain, which is also the only mode that tolerates rows removed by a retention purge.

Exit codes are the contract, and they are stable:

| Exit code | Meaning |
|---|---|
| `0` | Chain verified. |
| `1` | Chain break detected. |
| `2` | A row was unreadable: schema drift, malformed canonical JSON, or a database connection failure. |

`1` and `2` are deliberately distinct so a pipeline can route them differently: a chain break is a security page, an unreadable row is an ops page.

```shell
./craft password-policy/audit/verify --json | jq -e '.status == "ok"'
```

See [Audit verifier](../features/audit-verifier.md).

### `audit/schema`

Prints the per-event allowlist registry: for each audit event type, which `details` keys are permitted to be stored. This is the answer to an auditor asking what the plugin records.

```shell
./craft password-policy/audit/schema
```

| Option | Description |
|---|---|
| `--json` | Emit the registry as a single JSON object. |

### `audit/export`

Exports audit rows. Requires the Enterprise edition in both modes, because export is the read-side exposure of the audit log.

By default the rows stream to stdout, which is the form to use when piping into a SIEM or a log aggregator. With `--queue`, the command instead enqueues a job that writes a file to your configured filesystem and prints a one-time download token.

```shell
./craft password-policy/audit/export --format=jsonl > audit.jsonl
```

| Option | Description |
|---|---|
| `--days` | How many days back to export. Defaults to `365`. |
| `--format` | `csv` (default), `jsonl`, or `json`. |
| `--queue` | Write to a file via the queue instead of streaming to stdout. |

There is no `--from` or `--to` on this command. The window is expressed in days:

```shell
./craft password-policy/audit/export --days=30 --format=csv > last-30-days.csv
```

Prefer `jsonl` over `json`. `jsonl` streams, is byte-identical to what the queued job writes, and every line parses as an independent JSON document. `json` emits one large array, does not stream, prints a deprecation hint, and may be removed in 5.3.

See [Audit export](../features/audit-export.md).

### `audit/purge`

Deletes audit rows older than a day count. `gc/run` already does this on the configured window, so reach for `purge` only when you need a one-off deletion at a different threshold.

```shell
./craft password-policy/audit/purge --days=90
```

| Option | Description |
|---|---|
| `--days` | Retain this many days. Defaults to `365`. |

The delete is permanent. There is no soft-delete.

### `audit/generate-pii-key`

Generates a 32-byte HMAC key and writes it to your local `.env` as `CRAFT_AUDIT_PII_KEY`, then prints it so you can copy it into your production secret store.

```shell
./craft password-policy/audit/generate-pii-key
```

| Option | Description |
|---|---|
| `--force` | Overwrite an existing key. |

> [!WARNING]
> **Rotating the key orphans historical correlation**
>
> The key is the HMAC secret behind the audit log's `userIdentifier` column. Rotating it means existing rows can no longer be correlated to the users they describe. That is sometimes exactly what you want, as a GDPR Article 17 measure, but it is not reversible. Without `--force` the command refuses to overwrite, on purpose.

See [Audit logging](../features/audit-logging.md).

## SIEM forwarding

### `siem/run`

Enqueues the batched job that forwards pending audit rows to every active SIEM forwarder. Requires the Enterprise edition; on a lower edition the command writes to stderr and exits non-zero.

```shell
./craft password-policy/siem/run
```

Takes no options.

This is the only thing that starts a forward pass. Nothing enqueues the sweep for you, so without this command on a schedule your audit rows keep an empty `forwardedAt` and nothing reaches your SIEM. Schedule it, and make sure something is running the queue.

The job walks the audit log by watermark, stamping each row as a forwarder accepts it, so a run that is interrupted resumes from where it stopped rather than resending. Re-running the command while a sweep is still queued is harmless.

When no forwarder is currently active, the command prints `No active SIEM forwarders. Nothing enqueued.` and exits zero without queuing anything. A forwarder counts as inactive when it is disabled, or while its circuit breaker is inside the cooldown window. Suppressing the job in that case keeps a five-minute cron from filling the queue table with no-op jobs.

See [SIEM forwarders](../features/siem-forwarders.md) and [Cron setup](../operations/cron-setup.md).

## Webhooks

All four commands require the Enterprise edition.

### `webhook/create`

Registers a webhook endpoint and prints its generated signing secret to stdout exactly once. The database stores only ciphertext, so if you lose the printed value you rotate rather than recover it.

```shell
./craft password-policy/webhook/create \
    --url=https://hooks.example.com/audit \
    --name="Compliance dashboard" \
    --events=password_changed,hibp_breach_detected
```

| Option | Description |
|---|---|
| `--url` | The destination URL. Required. |
| `--name` | A display name for the control panel. |
| `--events` | Comma-separated event-class allowlist. Omit to receive every event. |

### `webhook/list`

Lists every registered endpoint as a table of id, enabled state, delivery cursor (the last audit row id delivered to that endpoint), and URL.

```shell
./craft password-policy/webhook/list
```

Takes no options.

### `webhook/rotate-secret`

Rotates an endpoint's signing secret and prints the new plaintext once. The endpoint id is a positional argument, not an option.

```shell
./craft password-policy/webhook/rotate-secret 42
```

Run `webhook/list` first if you do not know the id.

### `webhook/run`

Enqueues the batched job that delivers pending audit rows to every active webhook endpoint.

```shell
./craft password-policy/webhook/run
```

Takes no options.

This is the only thing that starts a delivery pass. Nothing enqueues the sweep for you, so without this command on a schedule no webhook is ever delivered. Schedule it, and make sure something is running the queue.

Each endpoint carries its own delivery cursor, the `lastDeliveredRowId` shown by `webhook/list`, so endpoints resume independently and one failing endpoint does not hold up the others.

When no endpoint is currently active, the command prints `No active webhook endpoints. Nothing enqueued.` and exits zero without queuing anything. An endpoint counts as inactive when it is disabled, or while its circuit breaker is inside the cooldown window.

See [Webhooks](../features/webhooks.md) and [Cron setup](../operations/cron-setup.md).

## See also

- [Cron setup](../operations/cron-setup.md): which of these to schedule, and how.
- [GC and retention](../operations/gc-and-retention.md): what each retention window controls.
- [Events](./events.md): events these commands fire.
