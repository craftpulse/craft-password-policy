# Compliance Dashboard (Enterprise)

The Compliance Dashboard is an Enterprise CP utility that surfaces the state of every audit-and-integration component the plugin ships (chain health, alert activity, pending SIEM forwards, retention status) in one place. It also exports HTML and CSV reports for evidence packages.

This page covers what's on the dashboard, the three available reports, the permission gates, and the operator workflow for the auditor's "show me what's happening" question.

## Access

The dashboard appears under **Utilities → Compliance dashboard** on Enterprise installs for any user with `pp:audit-view` permission. Pro and Lite editions don't see the utility at all: the registration listener gates on `getIsEnterprise()`.

## What's on the dashboard

### 1. Audit chain status

Shows the result of the most recent verifier run. The dashboard runs the verifier inline (with a 5-minute cache): the dashboard's own render time stays under a second even on large tables.

| State | Visual |
|---|---|
| Healthy chain | Green tip callout with the last-run timestamp + checked-row count |
| Broken chain | Amber warning callout with `firstBreakRowId`, a link to that audit row's detail, and an "investigate now" prompt |

The cache key is `pp:compliance:chain-health` with a 300-second TTL. Operators can force a fresh run by clicking the **Verify now** link in the section header: this triggers an immediate verifier call and updates the cache.

### 2. Activity in last 24h

A read-only table of alert cooldown fires grouped by event class. Shows what types of events triggered notification dispatches or SIEM forwards in the last 24 hours.

| Event class | Fires in last 24h |
|---|---|
| `breach_detected` | 12 |
| `password_changed` | 487 |
| `account_locked` | 3 |
| `force_reset_completed` | 19 |

Empty state: `"No alert activity in the last 24 hours."` rendered as a `<blockquote class="note">`.

Useful for the operator's eyeball check: is the right volume of activity flowing through the system? A site with 0 events in 24 hours might have its audit listener wiring broken; a site with 10,000 events might have an attack pattern worth investigating.

### 3. Pending SIEM forwarding

Count of audit rows with `forwardedAt IS NULL` (not yet forwarded), plus the oldest pending row's age.

| State | Visual |
|---|---|
| 0 pending | Green tip callout: "All audit rows have been forwarded." |
| ≥1 pending | Amber warning callout with the count + oldest age + a link to **SIEM forwarders** to investigate. |

The oldest age is rendered via `DateTimeHelper::humanDuration()`: "12 minutes", "3 hours", "2 days." If the oldest pending row is more than 24 hours old, the SIEM forwarder is likely stuck and warrants investigation. See [SIEM forwarders](./siem-forwarders.md#troubleshooting).

### 4. Retention

Shows the configured retention windows + the current state per retention-managed table:

| Table | Window | Oldest row | Projected next prune |
|---|---|---|---|
| Audit log | 365 days | 1 year, 2 days | 2026-05-15 02:00 UTC |
| Notification log | 30 days | 29 days, 11 hours | 2026-05-15 02:00 UTC |

The projected next prune assumes the `password-policy/gc/run` cron runs daily at 02:00 UTC. If you've configured a different cron schedule, the projected date is illustrative: the actual cleanup happens whenever your cron fires.

## Reports

Each dashboard section has a **Run HTML report** + **CSV download** link in its footer. The reports are deeper drilldowns useful for evidence packages; print-to-PDF the HTML output and attach the CSV for the raw rows.

Three reports ship:

### `audit-summary`

| Column | What's in it |
|---|---|
| Event class | One of the captured event types |
| Total | Cumulative count from earliest audit row to now |
| Last 30 days | Count from 30 days ago to now |

HTML format: a `<table class="data fullwidth">` with the same columns, plus aggregate totals at the bottom.

CSV format: header row + one data row per event class. UTF-8, RFC 4180 quoting.

URL: `password-policy/reports/audit-summary/html` or `/csv`.

### `alert-activity`

| Column | What's in it |
|---|---|
| Event class | One of the captured event types |
| Fires in last 24h | Count from 24 hours ago to now |
| Last fire | Timestamp of the most recent fire |

URL: `password-policy/reports/alert-activity/html` or `/csv`.

### `retention-projection`

| Column | What's in it |
|---|---|
| Table | One of the retention-managed tables (audit_log, notification_log, alert_cooldowns, password_history) |
| Retention window | Configured days |
| Oldest row | Age + timestamp |
| Projected next prune | Date when the GC will next clean rows from this table |
| Projected rows pruned | Count of rows older than the window |

URL: `password-policy/reports/retention-projection/html` or `/csv`.

## Permissions

| Permission | What it grants |
|---|---|
| `pp:audit-view` | Visibility into the Compliance Dashboard utility + every report. |
| `pp:audit-verify` | Ability to click the **Verify now** link to force a fresh chain verification (otherwise the cached state is shown). |

Edition-wise, the utility is Enterprise-only: both the registration listener (`getIsEnterprise()`) and the report controller (`beforeAction()`) gate on Enterprise. A Pro user with `pp:audit-view` granted by config wouldn't see the utility or the report URLs.

## URL structure

The dashboard utility renders at the standard Craft utility URL:

```
/admin/utilities/password-policy-compliance-dashboard
```

The reports controller registers two URL rules:

```
/admin/password-policy/reports/<report>/html
/admin/password-policy/reports/<report>/csv
```

Where `<report>` is one of `audit-summary`, `alert-activity`, `retention-projection`. Unknown report keys return 404.

> [!TIP]
> **Bookmarking reports**
>
> Each report URL is bookmarkable. Save the CSV URL for a compliance officer who wants to pull the retention projection monthly without navigating through the CP: they hit the URL, authenticate, and the CSV downloads.

## Performance contract

The dashboard runs on every CP page render of `/admin/utilities/password-policy-compliance-dashboard`. The aggregate service caches each section:

- `getTotals()`: 5-minute cache
- `getChainHealth()`: 5-minute cache (verifier walks the whole table)
- `getAlertCooldownActivity()`: 5-minute cache
- `getPendingForwards()`: 1-minute cache (operators may be actively unsticking a forwarder)
- `getRetentionStatus()`: 5-minute cache

Cold-cache dashboard render: 1-3 seconds on a typical install. Warm-cache render: under 500ms.

If you've configured a CP cache backend (Redis recommended for Enterprise installs), the cache hits are sub-millisecond.

## Integration with the rest of the plugin

- **Verifier results**: surfaced live via the inline chain-health check. See [Audit verifier](./audit-verifier.md).
- **Pending forwards**: link from the dashboard goes to **Password Policy → SIEM forwarders**, where operators can inspect each forwarder's enabled state and circuit breaker, and reset a circuit from the edit screen. There is no retry action: a pending row is retried by the next sweep on its own. See [SIEM forwarders](./siem-forwarders.md).
- **Retention status**: links to the GC console command + the [GC and retention](../operations/gc-and-retention.md) operations doc.
- **Alert activity**: links to **Password Policy → Notifications → Activity** for the per-event drill-through.

## See also

- [Audit logging](./audit-logging.md): the underlying surface the dashboard aggregates over.
- [Audit verifier](./audit-verifier.md): the chain-health source.
- [SIEM forwarders](./siem-forwarders.md): pending-forwards drilldown.
- [GC and retention](../operations/gc-and-retention.md): retention configuration + cron recipe.
- [Compliance frameworks](../operations/compliance-frameworks.md): clause anchors for the dashboard's evidence value.
