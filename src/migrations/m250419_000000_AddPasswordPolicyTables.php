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
use yii\db\Exception;

/**
 * Class m250419_000000_AddPasswordPolicyTables
 *
 * Upgrade migration from 5.1.x to 5.2.0. Creates new tables and seeds
 * password history from existing user password hashes.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m250419_000000_AddPasswordPolicyTables extends Migration
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
        // Use Install migration to create tables (it checks existence)
        $install = new Install();
        $install->safeUp();

        // Seed password history from existing user passwords
        $this->_seedPasswordHistory();

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeDown(): bool
    {
        $install = new Install();
        $install->safeDown();

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Seeds the password history table from existing user password hashes.
     *
     * Copies the current bcrypt hash from the users table for active, pending,
     * and suspended users. This prevents immediate password reuse after upgrade.
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
        // Temporarily disable Yii query logging during seed to avoid
        // logging password hashes in debug mode
        $enableLogging = Craft::$app->getDb()->enableLogging;
        $enableProfiling = Craft::$app->getDb()->enableProfiling;
        Craft::$app->getDb()->enableLogging = false;
        Craft::$app->getDb()->enableProfiling = false;

        try {
            // Seed all users who have a password hash — includes active,
            // pending, and suspended users. Covers reactivated suspended users.
            $users = (new Query())
                ->select(['id', 'password'])
                ->from(Table::USERS)
                ->where(['not', ['password' => null]])
                ->andWhere(['not', ['password' => '']])
                ->all();

            // Batch insert for performance
            $rows = [];
            $now = (new \DateTime())->format('Y-m-d H:i:s');

            foreach ($users as $user) {
                if (empty($user['password'])) {
                    continue;
                }

                $rows[] = [
                    $user['id'],
                    $user['password'],
                    $now,
                    \craft\helpers\StringHelper::UUID(),
                ];
            }

            if (!empty($rows)) {
                $this->batchInsert(
                    '{{%passwordpolicy_password_history}}',
                    ['userId', 'passwordHash', 'dateCreated', 'uid'],
                    $rows,
                );
            }
        } finally {
            // Restore logging settings
            Craft::$app->getDb()->enableLogging = $enableLogging;
            Craft::$app->getDb()->enableProfiling = $enableProfiling;
        }
    }
}
