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
 * Class m250419_100000_AddNotificationLogTable
 *
 * Adds the notification log table for expiry reminder dedup tracking.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m250419_100000_AddNotificationLogTable extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeUp(): bool
    {
        if ($this->db->tableExists('{{%passwordpolicy_notification_log}}')) {
            return true;
        }

        $this->createTable('{{%passwordpolicy_notification_log}}', [
            'id' => $this->primaryKey(),
            'userId' => $this->integer()->notNull(),
            'notificationType' => $this->string()->notNull(),
            'sentAt' => $this->dateTime()->notNull(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_notification_log}}', ['userId', 'notificationType', 'sentAt'], false);
        $this->addForeignKey(null, '{{%passwordpolicy_notification_log}}', ['userId'], Table::USERS, ['id'], 'CASCADE', null);

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function safeDown(): bool
    {
        $this->dropTableIfExists('{{%passwordpolicy_notification_log}}');

        return true;
    }
}
