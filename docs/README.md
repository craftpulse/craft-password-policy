# Documentation

Password Policy is a Craft CMS 5 plugin that handles password rules, breach detection, and compliance-grade audit logging. This is the index for everything you can read about it.

## I want to...

| | |
|---|---|
| [...install the plugin and ship a first policy](./user/getting-started.md) | Quick-start guide. |
| [...know what each edition includes](./user/editions.md) | Edition summary, every setting, and the gating rules. |
| [...upgrade from 5.1.x](./user/operations/upgrade-from-5.1.md) | Migration walkthrough plus the new `CRAFT_AUDIT_PII_KEY` env var setup. |
| [...set up cron for retention and the audit verifier](./user/operations/cron-setup.md) | Production cron recipes. |
| [...look up a console command](./user/reference/console-commands.md) | Every command the plugin ships, with its options. |
| [...map plugin features to compliance frameworks](./user/operations/compliance-frameworks.md) | Specific clause anchors for NIS2, NIST 800-63B Rev. 4, PCI DSS v4.0.1, ISO 27001:2022, SOC 2, GDPR. |
| [...know which events I can hook into](./user/reference/events.md) | Event catalog with payload tables and example listeners. |
| [...see the database schema](./user/reference/database-schema.md) | Tables, columns, indexes. |
| [...call the REST API](./user/reference/rest-api.md) | Enterprise: three read-only endpoints and the token registry. |
| [...call the AJAX validation endpoint](./user/reference/ajax-validate.md) | Request/response shapes for front-end consumers. |

## Features

Each feature has its own page covering what it does, how to configure it, and how to extend it.

### Policy enforcement

| | |
|---|---|
| [Per-group named policies](./user/features/per-group-policies.md) | Pro: CRUD manager, tri-state overrides, presets, conflict notices. |
| [Validators](./user/features/validators.md) | Length, complexity, sequential, repeated, contextual, common-password, history. |
| [Password history](./user/features/password-history.md) | Block reuse of the last N passwords with configurable retention (per-group overrides require Pro). |
| [Minimum change interval](./user/features/min-change-interval.md) | Pro: block a second password change within N hours, closing the history-flushing bypass. |
| [Blocklist](./user/features/blocklist.md) | Bundled common passwords (10k SecLists), custom dictionary editor, per-policy blocklist (Enterprise). |
| [User-index integration](./user/features/user-index.md) | Status columns, condition rules, element actions on the Users index. |

### Accounts and devices

| | |
|---|---|
| [Force reset](./user/features/force-reset.md) | Session invalidation, bulk reset, "must change on next login." |
| [Dormant accounts](./user/features/dormant-accounts.md) | Pro: find accounts with no recent sign-in, then report, notify, or suspend. |
| [Device tracking](./user/features/device-tracking.md) | Recognise a new device on sign-in. Capture on every edition, alert email on Enterprise. |

### Front-end and notifications

| | |
|---|---|
| [Front-end Twig builders](./user/features/frontend-twig.md) | Pro: `loginForm()`, `passwordChangeForm()`, `passwordResetForm()`, `passwordField()`, `strengthMeter()`. |
| [Notifications](./user/features/notifications.md) | Pro: per-site editable templates, activity log, resend, custom Twig template paths (Enterprise). |
| [Group alerts](./user/features/group-alerts.md) | Pro: route a copy of an alert to a per-group security contact, resolved from real group membership. |
| [Alert cooldowns](./user/features/alert-cooldowns.md) | Per-event-class dedup for notifications and forwarder retries. |

### Enterprise audit and integrations

| | |
|---|---|
| [Audit logging](./user/features/audit-logging.md) | Hash-chained log, privacy-by-design (HMAC userIdentifier + ipHash), per-event PII allowlist. |
| [Audit verifier CLI](./user/features/audit-verifier.md) | Independent end-to-end chain verification, auditor-runnable. |
| [Compliance dashboard](./user/features/compliance-dashboard.md) | Aggregates utility + HTML/CSV report controller. |
| [IP geolocation](./user/features/geoip.md) | Country code on audit rows and device alerts. Off by default, and carries an attribution obligation. |
| [SIEM forwarders](./user/features/siem-forwarders.md) | Syslog over TLS to rsyslog, syslog-ng, Graylog, QRadar, or any RFC 5424 receiver, or a JSON POST over HTTPS. |
| [Webhooks](./user/features/webhooks.md) | HMAC-signed HTTPS delivery with a replay-window timestamp and a stable event id per row. |
| [Audit export](./user/features/audit-export.md) | Streaming CSV/JSONL to any Craft filesystem, per-admin download tokens. |

## Operations

| | |
|---|---|
| [Installation](./user/getting-started.md) | Composer, Plugin Store, first-time setup. |
| [Upgrading from 5.1.x](./user/operations/upgrade-from-5.1.md) | Migration steps + `CRAFT_AUDIT_PII_KEY` provisioning. |
| [Cron + retention](./user/operations/cron-setup.md) | Which commands to schedule, and how. |
| [GC and retention](./user/operations/gc-and-retention.md) | What gets pruned, when, and how to override. |
| [Compliance frameworks](./user/operations/compliance-frameworks.md) | Clause-anchored mappings for evidence packages. |

## Reference

| | |
|---|---|
| [Console commands](./user/reference/console-commands.md) | Every command the plugin ships, with its options. |
| [Events](./user/reference/events.md) | Every event the plugin fires, with payload tables. |
| [Database schema](./user/reference/database-schema.md) | All 14 tables and their indexes. |
| [REST API](./user/reference/rest-api.md) | Enterprise: the three read-only endpoints and token management. |
| [AJAX validation](./user/reference/ajax-validate.md) | The `password-policy/validation/validate` endpoint. |

## See also

- [Plugin root README](../README.md)
- [CHANGELOG](../CHANGELOG.md)
- [Plugin Store listing](https://plugins.craftcms.com/password-policy)
- [GitHub issues](https://github.com/craftpulse/craft-password-policy/issues)
