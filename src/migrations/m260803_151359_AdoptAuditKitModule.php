<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\migrations;

use craft\db\Migration;
use craftpulse\auditkit\helpers\PluginAdoption;

/**
 * Class m260803_151359_AdoptAuditKitModule
 *
 * Adopts the plugin-era Audit Kit registration into the module world.
 *
 * Audit Kit 1.0.x shipped as a Craft plugin (`type: craft-plugin`); 1.1.0 ships
 * the same package as a library-shipped Yii module. After the Composer bump
 * Craft can no longer discover it, which strands two orphans on any install that
 * carried the plugin era: the `audit-kit` row in the `plugins` table, and the
 * `plugins.audit-kit` project config entry. Both describe a package Craft can no
 * longer resolve, and nothing removes them on its own. An entry left in the YAML
 * is worse than cosmetic: the next external `project-config/apply` reads it as a
 * plugin that still needs installing.
 *
 * {@see PluginAdoption::adopt()} is the kit's own helper and does all of it: it
 * re-tracks plugin-era migration history from `plugin:audit-kit` onto
 * `module:audit-kit` so the module migrator never re-runs a migration the plugin
 * era already applied, removes the project config entry with project config
 * events muted and the read-only flag temporarily lifted (mirroring Craft's own
 * forced plugin uninstall), then deletes the `plugins` row last, so a failure
 * part-way through leaves a registration the next adoption call retries from.
 *
 * Since kit 1.1.1 the project config removal is durable before `adopt()`
 * returns: the helper writes through `set(null, force: true)` and flushes with
 * events still muted, rather than leaving persistence to
 * `Application::EVENT_AFTER_REQUEST`, which a migration cannot count on reaching.
 * Nothing needs flushing here. The one case the helper deliberately leaves alone
 * is a run with external project config changes already pending, where Craft has
 * turned automatic YAML writing off for the whole migration; the stored config is
 * still updated, and `project-config/diff` is the check for the YAML.
 *
 * Since kit 1.1.2, `adopt()` also ends by running the kit migrator's `up()` on
 * the `module:audit-kit` track, which makes it a strict superset of the bare
 * pump and means this migration is the whole contract on the update path. PP's
 * own pump in {@see Install::safeUp()} stays: it covers the fresh-install path,
 * where Craft marks plugin migrations as applied without running them. The two
 * calls never collide, because `MigrationManager::up()` only applies what
 * `getNewMigrations()` reports and an applied migration is never a candidate
 * again.
 *
 * It never touches kit or consumer tables, so PP's hash-chained
 * `passwordpolicy_audit_log`, its exports and its anchors are unaffected.
 *
 * Every step is guarded, so this is the same one-liner every kit consumer ships:
 * the first consumer's migration to run does the work and the rest find nothing
 * to do. On an install that never carried the plugin, including a fresh install,
 * it writes nothing.
 *
 * This has to be a plugin migration on PP's own track rather than an addition to
 * {@see Install}, because it has to run on update, which is exactly what a
 * plugin migration does and what `Install` does not.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260803_151359_AdoptAuditKitModule extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws \Throwable from {@see PluginAdoption::adopt()} if one of its
     *     database writes or the project config removal fails.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeUp(): bool
    {
        PluginAdoption::adopt();

        return true;
    }

    /**
     * @inheritdoc
     *
     * Irreversible by design. Reverting would mean reinstating a plugin
     * registration for a package that is no longer a plugin, which is not a
     * state worth being able to return to.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeDown(): bool
    {
        echo "m260803_151359_AdoptAuditKitModule cannot be reverted.\n";

        return false;
    }
}
