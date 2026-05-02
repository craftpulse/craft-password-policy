<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\migrations;

use Craft;
use craft\db\Migration;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\enums\ChangeReason;
use yii\db\Exception;

/**
 * Class m260429_224908_UpgradeTo520Schema
 *
 * Consolidated upgrade migration from 5.1.1 to 5.2.0.
 *
 * 5.1.1 had no plugin tables and stored password rules under `pwned` /
 * `pwnedFailMode` keys in project config. This migration:
 *
 * 1. Creates the full 5.2.0 schema (all six tables) by reusing
 *    {@see Install::safeUp()} — each table is guarded by `tableExists`,
 *    so re-runs are safe.
 * 2. Seeds `passwordpolicy_password_history` from current user password
 *    hashes — idempotent (skipped when the table already has rows).
 *    Yii query logging is suppressed during the seed so bcrypt hashes
 *    never reach debug logs.
 * 3. Renames `pwned` → `hibp` and `pwnedFailMode` → `hibpFailMode` in
 *    the plugin's project config settings.
 * 4. Drops the legacy `groupPolicies` project config key. That field
 *    was an in-cycle 5.2.0-alpha precursor to named policies (table-
 *    backed) and never shipped to a stable release. Real 5.1.1 → 5.2.0
 *    upgraders never had it; this is purely a defensive scrub.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260429_224908_UpgradeTo520Schema extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws Exception
     *
     * @author CraftPulse
     */
    public function safeUp(): bool
    {
        (new Install())->safeUp();
        $this->_seedPasswordHistory();
        $this->_renameProjectConfigKeys();

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeDown(): bool
    {
        return (new Install())->safeDown();
    }

    // Private Methods
    // =========================================================================

    /**
     * Seeds the password history table from existing user password hashes,
     * preventing immediate password reuse after upgrade.
     *
     * Idempotent: if any history rows already exist (re-run, partial prior
     * run, or someone changed a password between schema-create and seed)
     * the seed is skipped.
     *
     * Suppresses Yii query logging/profiling during the seed so bcrypt
     * hashes never appear in debug-mode logs.
     *
     * Each seeded row gets `changeReason = ChangeReason::MigrationSeed`
     * so Phase G audit-log queries can distinguish migration-seeded rows
     * from real user-/admin-driven changes after upgrade.
     *
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _seedPasswordHistory(): void
    {
        $existing = (new Query())
            ->from('{{%passwordpolicy_password_history}}')
            ->limit(1)
            ->exists();

        if ($existing) {
            return;
        }

        $db = Craft::$app->getDb();
        $enableLogging = $db->enableLogging;
        $enableProfiling = $db->enableProfiling;
        $db->enableLogging = false;
        $db->enableProfiling = false;

        try {
            $users = (new Query())
                ->select(['id', 'password'])
                ->from(Table::USERS)
                ->where(['not', ['password' => null]])
                ->andWhere(['not', ['password' => '']])
                ->all();

            $rows = [];
            $now = (new \DateTime())->format('Y-m-d H:i:s');

            // Migration-seed rows record `ChangeReason::MigrationSeed` so
            // Phase G audit-log queries can distinguish "the upgrade
            // migration filled this in" from "a user/admin actively
            // changed their password." No `changedByUserId` / IP / UA —
            // the migration is the operator, not a human.
            $reason = ChangeReason::MigrationSeed->value;

            foreach ($users as $user) {
                if (empty($user['password'])) {
                    continue;
                }

                $rows[] = [
                    $user['id'],
                    $user['password'],
                    $reason,
                    $now,
                    StringHelper::UUID(),
                ];
            }

            if (!empty($rows)) {
                $this->batchInsert(
                    '{{%passwordpolicy_password_history}}',
                    ['userId', 'passwordHash', 'changeReason', 'dateCreated', 'uid'],
                    $rows,
                );
            }
        } finally {
            $db->enableLogging = $enableLogging;
            $db->enableProfiling = $enableProfiling;
        }
    }

    /**
     * Renames `pwned` → `hibp` and `pwnedFailMode` → `hibpFailMode` in the
     * plugin's project config settings, and drops the legacy `groupPolicies`
     * key entirely.
     *
     * Project config events are muted during the write so any cascading
     * subscribers don't fire mid-migration.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renameProjectConfigKeys(): void
    {
        $settings = Craft::$app->getProjectConfig()->get('plugins.password-policy.settings');

        if ($settings === null) {
            return;
        }

        $changed = false;

        if (array_key_exists('pwned', $settings)) {
            $settings['hibp'] = $settings['pwned'];
            unset($settings['pwned']);
            $changed = true;
        }

        if (array_key_exists('pwnedFailMode', $settings)) {
            $settings['hibpFailMode'] = $settings['pwnedFailMode'];
            unset($settings['pwnedFailMode']);
            $changed = true;
        }

        if (array_key_exists('groupPolicies', $settings)) {
            unset($settings['groupPolicies']);
            $changed = true;
        }

        if (!$changed) {
            return;
        }

        $projectConfig = Craft::$app->getProjectConfig();
        $wasMuted = $projectConfig->muteEvents;
        $projectConfig->muteEvents = true;

        try {
            $projectConfig->set('plugins.password-policy.settings', $settings);
        } finally {
            $projectConfig->muteEvents = $wasMuted;
        }
    }
}
