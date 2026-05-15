# Documentation

Password Policy is a Craft CMS 5 plugin that handles password rules, breach detection, and compliance-grade audit logging — all in one plugin. This is the index for everything you can read about it.

## I want to…

| | |
|---|---|
| 🚀 […install the plugin and ship a first policy](./user/getting-started.md) | Quick-start guide. |
| 💎 […know what each edition includes](./user/editions.md) | Lite / Pro / Enterprise feature matrix with framework anchors. |
| ⬆️ […upgrade from 5.1.x](./user/operations/upgrade-from-5.1.md) | Single-migration walkthrough plus the new `CRAFT_AUDIT_PII_KEY` env var setup. |
| ⏰ […set up cron for retention and the audit verifier](./user/operations/cron-setup.md) | Production cron recipes. |
| 📜 […map plugin features to compliance frameworks](./user/operations/compliance-frameworks.md) | Specific clause anchors for NIS2, NIST 800-63B Rev. 4, PCI DSS v4.0.1, ISO 27001:2022, SOC 2, GDPR. |
| 🎟️ […know which events I can hook into](./user/reference/events.md) | Event catalog with payload tables and example listeners. |
| 🗄️ […see the database schema](./user/reference/database-schema.md) | Tables, columns, indexes. |
| 🤝 […call the AJAX validation endpoint](./user/reference/ajax-validate.md) | Request/response shapes for front-end consumers. |

## Features

Each feature has its own page covering what it does, how to configure it, and how to extend it.

### Policy enforcement

| | |
|---|---|
| [Per-group named policies](./user/features/per-group-policies.md) | Pro: CRUD manager, tri-state overrides, presets, conflict notices. |
| [Validators](./user/features/validators.md) | Length, complexity, sequential, repeated, contextual, common-password, history. |
| [Password history](./user/features/password-history.md) | Pro: block reuse of the last N passwords with configurable retention. |
| [Blocklist](./user/features/blocklist.md) | Bundled common passwords (10k SecLists), custom dictionary editor, per-policy blocklist (Enterprise). |
| [User-index integration](./user/features/user-index.md) | Status columns, condition rules, element actions on the Users index. |

### Front-end + admin UX

| | |
|---|---|
| [Front-end Twig builders](./user/features/frontend-twig.md) | Pro: `loginForm()`, `passwordChangeForm()`, `passwordResetForm()`, `passwordField()`, `strengthMeter()`. |
| [Notifications](./user/features/notifications.md) | Pro: per-site editable templates, activity log, resend, custom Twig template paths (Enterprise). |
| [Force reset](./user/features/force-reset.md) | Session invalidation, bulk reset, "must change on next login." |

### Enterprise audit + integrations

| | |
|---|---|
| [Audit logging](./user/features/audit-logging.md) | Hash-chained log, privacy-by-design (HMAC userIdentifier + ipHash), per-event PII allowlist. |
| [Audit verifier CLI](./user/features/audit-verifier.md) | Independent end-to-end chain verification, auditor-runnable. |
| [Compliance dashboard](./user/features/compliance-dashboard.md) | Aggregates utility + HTML/CSV report controller. |
| [SIEM forwarders](./user/features/siem-forwarders.md) | Syslog-over-TLS to Splunk HEC, Datadog Logs, or any RFC 5424 receiver. |
| [Webhooks](./user/features/webhooks.md) | HMAC-signed delivery with replay-window protection and idempotency UUIDs. |
| [Audit export](./user/features/audit-export.md) | Streaming CSV/JSONL to any Craft filesystem, per-admin download tokens. |
| [Alert cooldowns](./user/features/alert-cooldowns.md) | Per-event-class dedup for notifications and forwarder retries. |

## Operations

| | |
|---|---|
| [Installation](./user/getting-started.md) | Composer, Plugin Store, first-time setup. |
| [Upgrading from 5.1.x](./user/operations/upgrade-from-5.1.md) | Migration steps + `CRAFT_AUDIT_PII_KEY` provisioning. |
| [Cron + retention](./user/operations/cron-setup.md) | `password-policy/gc/run` and `password-policy/audit/verify` cron recipes. |
| [GC and retention](./user/operations/gc-and-retention.md) | What gets pruned, when, and how to override. |
| [Compliance frameworks](./user/operations/compliance-frameworks.md) | Clause-anchored mappings for evidence packages. |

## Reference

| | |
|---|---|
| [Events](./user/reference/events.md) | Every event the plugin fires, with payload tables. |
| [Database schema](./user/reference/database-schema.md) | All tables and indexes. |
| [AJAX validation](./user/reference/ajax-validate.md) | The `/password-policy/validate` endpoint. |

## How the docs are organised

- **`docs/user/`** is for end users and integrators — anything we'd publish on the Plugin Store or hand to a partner. Plain Markdown, no badges, no fancy tooling.
- **`docs/internal/`** is for plugin maintainers and AI agents. It carries the handover doc, master plan, manual-test register, ideas log. Skip it unless you're contributing to the plugin itself.

## See also

- [Plugin root README](../README.md)
- [CHANGELOG](../CHANGELOG.md)
- [Plugin Store listing](https://plugins.craftcms.com/password-policy)
- [GitHub issues](https://github.com/craftpulse/craft-password-policy/issues)
