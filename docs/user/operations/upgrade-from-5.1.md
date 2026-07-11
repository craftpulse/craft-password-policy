# Upgrading from 5.1.x

5.2.0 is a major release adding Pro and Enterprise edition tiers. The upgrade ships a single consolidated database migration that renames the legacy `pwned` setting to `hibp`, adds the new tables for password history / blocklist / notifications / audit / forwarders / webhooks, and preserves every existing 5.1.x setting and password-history entry.

This guide walks you through the upgrade, the one new environment variable Enterprise installs need, and what to verify after `./craft up`.

## Before you start

- Take a database backup. The migration is reversible but reverting after a failure is faster from a backup than a rollback.
- Note your current 5.1.x edition (Lite is the only option in 5.1.x). 5.2.0 starts Lite by default; you upgrade to Pro or Enterprise after the schema migration lands.
- If you've customised `config/password-policy.php`, review the [Settings key renames](#settings-key-renames) below — `pwned` → `hibp` is the one breaking change in config-file land.

## The basic upgrade

In your Craft project root:

```bash
composer update craftpulse/craft-password-policy
./craft up
```

`composer update` pulls 5.2.0. `./craft up` applies the migration that ships in the new release — your install is now on 5.2.0 in Lite mode with all your existing 5.1.x settings preserved.

That's it for the Lite tier upgrade.

## Verifying after `./craft up`

Spot-check a few things to confirm the migration applied cleanly:

```bash
# Schema version should be 2.11.0 or later
./craft project-config/get plugins.password-policy.schemaVersion

# Settings — the renamed key should resolve under its new name
./craft project-config/get plugins.password-policy.settings.hibp

# Password history rows from 5.1.x carry forward
./craft password-policy/blocklist/stats
```

The CP should show **Password Policy → Settings** with the redesigned sidebar (Policy / Validation / Monitoring / Audit sections). On Lite the Pro-only rows (Group Policies, Compliance Presets) are omitted entirely; they appear once you switch to Pro.

## Upgrading to Pro

In `config/project/project.yaml`:

```yaml
plugins:
  password-policy:
    edition: pro
```

Bump `dateModified` at the top of `project.yaml` (Craft uses this as the project-config change-detection timestamp), then:

```bash
./craft up
```

The Pro subnav (Policies, Blocklist, Notifications) appears in the CP under **Password Policy**. None of your Lite settings change — Pro is purely additive.

> ::: warning Don't set the edition via `app.php` `pluginConfigs`
> Edition switching goes through project config, not the runtime `app.php` `pluginConfigs` hash. The `pluginConfigs` approach skips the project-config rebuild and won't surface the new subnav items. Use `project.yaml` + `./craft up`.
> :::

### Configuring per-group policies

After upgrading, open **Settings → Password Policy → Per-Group Policies** and toggle **Enable per-group policies**. The **Policies** subnav now appears.

Visit **Password Policy → Policies → New policy** and pick a preset (NIST 800-63B Rev. 4, OWASP ASVS L1, PCI-DSS v4.0.1, or Strict Enterprise) as a starting template. See [Per-Group Policies](../features/per-group-policies.md).

### Seeding the blocklist

The bundled common-password list (10,000 entries from SecLists) seeds automatically when you enable the `checkCommonPasswords` validator for the first time. To trigger seeding manually:

```bash
./craft password-policy/blocklist/seed-common
```

See [Blocklist](../features/blocklist.md).

## Upgrading to Enterprise

```yaml
plugins:
  password-policy:
    edition: enterprise
```

```bash
./craft up
```

Enterprise adds:

- The audit log + verifier CLI + compliance dashboard.
- SIEM forwarders + webhook delivery.
- Audit export + filesystem destinations.
- Per-policy custom blocklist tab on the policy edit screen.
- Custom Twig template paths for email notifications.

**The Enterprise tier needs one additional one-time setup step** — provisioning the dedicated audit-PII HMAC key.

### Provisioning `CRAFT_AUDIT_PII_KEY`

The audit log hashes user emails via HMAC-SHA-256 keyed by a secret that's **independent of Craft's `securityKey`**. This lets you rotate the audit-PII key without breaking sessions, CSRF tokens, or anything else `securityKey` anchors. See [Audit logging → Privacy guarantees](../features/audit-logging.md#privacy-guarantees) for the full rationale.

Generate the key once:

```bash
./craft password-policy/audit/generate-pii-key
```

The command:

- Generates 32 random bytes (64 hex chars — same shape as `securityKey`).
- Writes `CRAFT_AUDIT_PII_KEY` to your local `.env` file.
- Prints the key to stdout for copy-paste to other environments.

Set the same env var on every environment that runs the plugin — local, staging, production, CI for tests that touch audit-log rows. Rows hashed in one environment with a different key are not correlatable from another.

The default `config/password-policy.php` template wires the env var through:

```php
<?php

use craft\helpers\App;

return [
    'auditPiiKey' => App::env('CRAFT_AUDIT_PII_KEY'),
];
```

If `CRAFT_AUDIT_PII_KEY` is unset, the plugin falls back to `securityKey` — fresh installs still produce hashable rows. **The privacy property (rotation without site breakage) only applies once you've set the env var explicitly.** Production deployments should always set it.

### Configuring forwarders (optional)

Enterprise adds SIEM + webhook delivery surfaces but doesn't auto-configure any endpoints — that's a deliberate operator decision. See [SIEM forwarders](../features/siem-forwarders.md) and [Webhooks](../features/webhooks.md) for the setup walkthroughs.

## Settings key renames

The 5.2.0 migration renames one setting:

| 5.1.x | 5.2.0 |
|---|---|
| `pwned` | `hibp` |
| `pwnedFailMode` | `hibpFailMode` |

The migration handles both `project.yaml` and direct DB rows. If you've also customised `config/password-policy.php` with a `'pwned' => true` row, the `SettingsModel` accepts the legacy key for backward compatibility and aliases it to `hibp` with a `WARNING`-level log entry:

```
WARNING: Setting key "pwned" is deprecated; use "hibp" instead. (config/password-policy.php)
```

The alias works permanently — there's no timeline for removing it. Migrate the key in your config file when convenient to clear the log warnings.

## Schema changes

The migration `m260429_224908_UpgradeTo520Schema` creates the following tables on the upgrade path. Fresh installs run `Install.php` which produces the same schema. Both code paths are idempotent — re-running them on a tree that already has the tables is a no-op.

| Table | Purpose |
|---|---|
| `passwordpolicy_password_history` | bcrypt hashes of previous passwords for reuse prevention. |
| `passwordpolicy_blocklist` | Bundled common passwords + custom dictionary entries. |
| `passwordpolicy_policies` | Pro: named policies (also a Craft element table). |
| `passwordpolicy_policy_groups` | Junction: policies × user groups. |
| `passwordpolicy_notification_templates` | Pro: per-(key, siteId) editable email templates. |
| `passwordpolicy_notification_log` | Activity log of every notification dispatch (also a Craft element table). |
| `passwordpolicy_user_state` | Per-user state: last breach check, breached recently, pending change reason. |
| `passwordpolicy_audit_log` | Enterprise: hash-chained audit rows (also a Craft element table). |
| `passwordpolicy_alert_cooldowns` | G7: per-(eventClass, cooldownKey) dedup. |
| `passwordpolicy_siem_forwarders` | Enterprise: configured SIEM endpoints. |
| `passwordpolicy_webhook_endpoints` | Enterprise: configured webhook endpoints. |

Three of these tables (`policies`, `notification_log`, `audit_log`) back Craft 5 element types — their `id` columns are foreign keys to `craft_elements.id` with FK CASCADE on element delete.

For the column-by-column reference, see [Database schema](../reference/database-schema.md).

## Rolling back

To roll back to 5.1.x:

1. Stop the Craft application (or put the site in offline mode).
2. Restore the pre-upgrade database backup.
3. Composer-downgrade the plugin: `composer require craftpulse/craft-password-policy:^5.1`.
4. Restart the application.

The 5.2.0 migration does not have a clean `safeDown()` that produces a 5.1.x-shaped database — there's too much new infrastructure to roll back cleanly via DDL. The supported rollback path is "restore from backup," which is why we recommend taking one before the upgrade.

## Troubleshooting

### `./craft up` fails with a foreign-key error

Most common cause: existing data in `users` references group IDs that no longer exist (legacy soft-deleted groups). Run:

```bash
./craft project-config/sync
./craft up
```

If that doesn't resolve, inspect the migration's error output for the specific table + constraint name. The migration is idempotent — re-running it after fixing the underlying issue is safe.

### The `hibp` setting reads as `null` after upgrade

The legacy `pwned` key should auto-migrate. If it didn't, check:

```bash
./craft project-config/get plugins.password-policy.settings.pwned
./craft project-config/get plugins.password-policy.settings.hibp
```

If both return `null`, the setting was never persisted to project config (it lived only in `config/password-policy.php`). The `SettingsModel` alias should still resolve the legacy key from the config file; if not, manually rename `pwned` → `hibp` in `config/password-policy.php` and re-`./craft up`.

### Pro/Enterprise features missing in the CP after switching editions

Hard-refresh the CP (Cmd+Shift+R / Ctrl+Shift+R). Craft caches the project-config interpretation for the duration of a request; the newly-unlocked subnav items and settings sections appear on the next render.

If they still don't appear, verify the edition value via:

```bash
./craft project-config/get plugins.password-policy.settings.edition
```

It should be `pro` or `enterprise` (lowercase). Re-run `./craft up` if needed.

### CSRF errors on the front-end after upgrade

5.2.0's front-end Twig builders register a CSRF-required AJAX endpoint at `password-policy/validation/validate`. If your consumer site templates were using the lowercase `craft.passwordpolicy.*` variable handle, the upgrade preserves backward compatibility (both `craft.passwordPolicy` and `craft.passwordpolicy` work). But the new builders ship updated default selectors and may require front-end markup changes — see [Front-end Twig builders](../features/frontend-twig.md).

## See also

- [Getting Started](../getting-started.md) — first-time install walkthrough.
- [Edition Matrix](../editions.md) — what each tier ships.
- [Compliance frameworks](./compliance-frameworks.md) — clause-by-clause framework mapping for the Pro and Enterprise features.
- [Cron setup](./cron-setup.md) — production cron recipes for GC + audit verification.
