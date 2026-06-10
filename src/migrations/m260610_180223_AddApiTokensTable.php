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

use craft\db\Migration;
use craft\db\Table;

/**
 * m260610_180223_AddApiTokensTable migration.
 *
 * Adds `passwordpolicy_api_tokens` to sites already past 5.0 (fresh installs
 * get it from {@see Install::_createApiTokensTable()}). Backs Feature 2
 * (read-only REST API, Enterprise) — one row per issued Bearer token.
 *
 * Security: the plaintext token is NEVER persisted. Only its SHA-256
 * `tokenHash` (unique lookup key) and a short `tokenPrefix` (first 8 chars,
 * CP display) land on the row. The plaintext is returned exactly once at
 * issue time. `createdByUserId` FK SET NULL — a token outlives the admin who
 * issued it; revocation is an explicit operator action.
 *
 * Idempotent — guarded by `tableExists()` so a re-run on a fully-applied
 * site is a no-op. Mirror of `Install::_createApiTokensTable()`; the two are
 * kept in lockstep so fresh installs and upgraders land on identical schema
 * without depending on each other.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260610_180223_AddApiTokensTable extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeUp(): bool
    {
        $table = '{{%passwordpolicy_api_tokens}}';

        if ($this->db->tableExists($table)) {
            return true;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'name' => $this->string()->notNull(),
            'tokenHash' => $this->char(64)->notNull(),
            'tokenPrefix' => $this->string(16)->notNull(),
            'scopes' => $this->json()->null(),
            'lastUsedAt' => $this->dateTime()->null(),
            'expiresAt' => $this->dateTime()->null(),
            'createdByUserId' => $this->integer()->null(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['tokenHash'], true);
        $this->createIndex(null, $table, ['expiresAt'], false);
        $this->addForeignKey(null, $table, ['createdByUserId'], Table::USERS, ['id'], 'SET NULL', null);

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeDown(): bool
    {
        $this->dropTableIfExists('{{%passwordpolicy_api_tokens}}');

        return true;
    }
}
