# Dormant Accounts

Finds accounts that have not signed in for a long time, and either reports them, warns them, or suspends them. Requires the Pro edition.

Off by default, and it does not run on its own even once enabled: the scan is a console command you schedule. That is on purpose. An account-suspending job that fires without an operator asking for it is how a plugin locks out a customer's finance director on a Sunday.

## Why bother

A dormant account is an account nobody is watching. Its password is old, its owner may have left, and if its credentials leak, nobody notices the unfamiliar sign-in because nobody is expecting a familiar one.

PCI DSS v4.0.1 §8.2.6 makes this explicit: inactive accounts must be removed or disabled within 90 days. That is where the 90-day default comes from.

## Turning it on

None of these settings have control panel fields. Set them in `config/password-policy.php`:

```php
return [
    'inactiveAccountsEnabled' => true,
    'inactiveThresholdDays' => 90,
    'inactiveAction' => 'report',
    'inactiveNotifyAdmin' => false,
];
```

| Setting | Default | Description |
|---|---|---|
| `inactiveAccountsEnabled` | `false` | Whether dormant-account handling is on at all. |
| `inactiveThresholdDays` | `90` | Days of inactivity before an account counts as dormant. |
| `inactiveAction` | `report` | What the scan does: `report`, `notify`, or `suspend`. |
| `inactiveNotifyAdmin` | `false` | Also alert the admin each time the scan actions an account. |

The **Inactive accounts** screen appears in the Password Policy nav on Pro for anyone holding `pp:inactive-view`, whether or not the feature is enabled. With it off, the screen says so rather than showing an empty list.

## What counts as inactive

An account is dormant when its last sign-in is older than the threshold. An account that has **never** signed in falls back to its creation date, so a provisioned-and-forgotten account is caught rather than skipped forever.

The detection query deliberately skips accounts that are already suspended, still pending activation, or locked out. It also skips soft-deleted users, drafts, and revisions. Suspended accounts being excluded is what makes the `suspend` action safely repeatable: once the scan suspends an account, later runs no longer see it.

A threshold of `0` or less matches nothing, rather than matching everyone. A misconfigured threshold should do nothing, not flag your entire user base.

## The three actions

### `report`

Does nothing to the account. The scan records that it saw it, and the account appears on the Inactive accounts screen.

This is the default, and it is where to start. Run in report mode for one threshold period and read the list before you consider anything destructive. On most sites the first list contains at least one account somebody still needs.

### `notify`

Emails the dormant user the `inactive-account` notification, and otherwise leaves the account alone.

Use this as the step between reporting and suspending. It gives a real user a chance to sign in and clear themselves off the list, which is both kinder and cheaper than a support ticket asking why they are locked out.

### `suspend`

Suspends the account using Craft's own native suspension, the same state the Users index sets. It is reversible: unsuspend from the control panel and the account works again. No data is deleted, and the user's content is untouched.

Already-suspended accounts are skipped, so the action is idempotent.

The PCI DSS and Strict Enterprise presets opt into `suspend`, because those frameworks ask for it. Nothing else does.

> [!WARNING]
> **Rehearse suspend before you enable it**
>
> Run the scan with `--mode=report --threshold=<your intended value>` and read the resulting list first. The overrides exist for exactly this. Switching `inactiveAction` to `suspend` without having seen the list once is how a scheduled job locks out an account somebody depended on.

## Running the scan

```shell
./craft password-policy/inactive/scan
```

| Option | Description |
|---|---|
| `--threshold` | Override `inactiveThresholdDays` for this run. |
| `--mode` | Override `inactiveAction`: `report`, `notify`, or `suspend`. |

The command enqueues a batched job that processes 100 accounts at a time. Each batch re-runs the detection query, so a retried batch does not re-action accounts the previous batch already handled.

Weekly is usually the right cadence. Dormancy is measured in months, so a daily scan buys nothing and, under `suspend`, gives you a daily chance to be surprised.

```cron
0 4 * * 0 cd /path/to/project && ./craft password-policy/inactive/scan
```

On a sub-Pro install, or with `inactiveAccountsEnabled` off, the command writes to stderr and exits non-zero rather than enqueuing a job that would do nothing. That makes a misconfiguration visible in your cron log instead of silent.

A single account's failure logs and the batch continues, so one unsaveable user cannot strand the rest of the run.

## The Inactive accounts screen

**Password Policy → Inactive accounts** (Pro, `pp:inactive-view`) is a read-only report. It lists the accounts currently past the threshold, most stale first:

| Column | Description |
|---|---|
| User | Username, linking to the user's edit screen. |
| Email | The account's email address. |
| Last activity | Last sign-in, or "Never" for an account that never signed in. |
| Days inactive | Days since that last activity. |

The screen recomputes the list live from the threshold. It is not a log of what the scan did, and it does not wait for a scan to run: turn the feature on and the list is populated immediately, before you have scheduled anything. That is the safest way to read it, because it tells you what a scan *would* do.

There are no actions on this screen. Suspending is the scan's job, and unsuspending is Craft's.

## Audit and events

On Enterprise with audit logging on, each actioned account writes an `account_inactive` audit row. The row's `source` column is `cli`, and its `details` carry the action taken plus `source: inactive_scan` so you can tell a scan-driven row from any other. The row records the action, not the user's email: the identifier is HMAC-hashed like every other audit row.

`inactiveNotifyAdmin` additionally routes an admin security alert per actioned account, through the Enterprise admin-alert surface. On a sub-Enterprise install the alert is skipped and logged rather than failing the scan, because the admin alert is an add-on to the action, never the point of it.

The `EVENT_ACCOUNT_INACTIVE` event fires once per actioned account, in every mode, after the action has taken effect. See [Events](../reference/events.md#accountinactiveevent).

## See also

- [Console commands](../reference/console-commands.md#inactivescan): the full option reference.
- [Cron setup](../operations/cron-setup.md): scheduling the scan.
- [Compliance frameworks](../operations/compliance-frameworks.md): PCI DSS §8.2.6 and related clauses.
- [Events](../reference/events.md): the `AccountInactiveEvent` payload.
