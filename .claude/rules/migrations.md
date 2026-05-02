<!-- craftcms-claude-skills -->
# Migrations — craftpulse/craft-password-policy

## Generation — always via Craft CLI

```bash
ddev craft migrate/create <DescriptiveName> --plugin=password-policy
```

**Never hand-pick filenames or timestamps.** The container clock authors them; the host clock drifts and the alphabetical ordering breaks. The Craft CLI also wires the right namespace + base class.

## Idempotent guards

Every migration must be safe to re-run. Common patterns:

- **Table create**: `if ($this->db->getSchema()->getTableSchema(Table::FOO) === null) { $this->createTable(...); }`
- **Column add**: check `getTableSchema()->getColumn($name)` before `addColumn()`.
- **Project-config rename / seed**: skip if target key already exists or seed table already non-empty.
- **History seed (bcrypt batch insert)**: skip when the table already has rows. The original `m250419_*` migration lacked this guard and would have corrupted state on re-run — fixed in `m260429_224908_UpgradeTo520Schema`.

## Project-config writes

Wrap in `muteEvents` try/finally:

```php
$projectConfig = Craft::$app->getProjectConfig();
$wasMuted = $projectConfig->muteEvents;
$projectConfig->muteEvents = true;
try {
    $projectConfig->set('plugins.password-policy.settings.foo', $newValue);
} finally {
    $projectConfig->muteEvents = $wasMuted;
}
```

Prevents internal subscribers from re-entering during the write. Critical for plugin-managed key renames (e.g. `pwned` → `hibp`).

## Bcrypt seed loops

Toggle `enableLogging` + `enableProfiling` off before the loop, restore in `finally`. Yii's debug logger would otherwise capture the hashes at SQL bind time.

## `Install.php`

Canonical schema for fresh installs. Ordered correctly for FK dependencies (policies before policy_groups before blocklist before audit_log etc.). When adding a new table:

1. Add `_create<Name>Table()` private method to `Install.php`.
2. Call it from `safeUp()` in correct FK order.
3. Add a corresponding drop in `safeDown()` in reverse order.
4. Bump `PasswordPolicy::$schemaVersion`.
5. Author a dated migration that calls the same private method (or `(new Install())->safeUp()` for upgrade-only migrations) for sites already past 5.0.

## Schema version bump

`src/PasswordPolicy.php::$schemaVersion`. Bump on any structural change. Used by Craft to determine "needs craft up" state.

## Migration tracking rows

Stale rows in the `migrations` table for deleted/replaced migration files are cosmetic — Craft ignores them. Don't try to clean them up; you'll just confuse downstream upgrades.

## Edition switching for testing

```bash
# Edit cms/config/project/project.yaml:
#   plugins.password-policy.settings.edition: lite
# Bump dateModified at the top of project.yaml
ddev craft up
```

Don't use `app.php` `pluginConfigs` hacks. Project config is the source of truth.
