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
use craft\db\Table;

/**
 * m260610_150859_AddKnownDevicesTable migration.
 *
 * Adds `passwordpolicy_known_devices` to sites already past 5.0 (fresh
 * installs get it from {@see Install::_createKnownDevicesTable()}). Backs
 * Feature 1 device tracking — one row per (user, device fingerprint) seen
 * at login. Capture is universal across editions per
 * `project_audit_capture_principle.md`; the table ships everywhere even
 * though the new-device alert email + audit exposure are Enterprise-gated.
 *
 * Idempotent — guarded by `tableExists()` so a re-run on a fully-applied
 * site is a no-op. Mirror of `Install::_createKnownDevicesTable()`; the two
 * are kept in lockstep so fresh installs and upgraders land on identical
 * schema without depending on each other.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260610_150859_AddKnownDevicesTable extends Migration
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
        $table = '{{%passwordpolicy_known_devices}}';

        if ($this->db->tableExists($table)) {
            return true;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'userId' => $this->integer()->notNull(),
            'fingerprint' => $this->char(64)->notNull(),
            'deviceLabel' => $this->string()->null(),
            'maskedIp' => $this->string(45)->null(),
            'siteId' => $this->integer()->null(),
            'firstSeenAt' => $this->dateTime()->notNull(),
            'lastSeenAt' => $this->dateTime()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['fingerprint'], false);
        $this->createIndex(null, $table, ['lastSeenAt'], false);
        $this->createIndex(null, $table, ['userId', 'fingerprint'], true);

        $this->addForeignKey(null, $table, ['userId'], Table::USERS, ['id'], 'CASCADE', null);
        $this->addForeignKey(null, $table, ['siteId'], Table::SITES, ['id'], 'SET NULL', null);

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
        $this->dropTableIfExists('{{%passwordpolicy_known_devices}}');

        return true;
    }
}
