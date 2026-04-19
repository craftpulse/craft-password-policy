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
 * Class Install
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class Install extends Migration
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
        $this->_createPasswordHistoryTable();
        $this->_createAuditLogTable();
        $this->_createBlocklistTable();
        $this->_createNotificationLogTable();

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
        $this->dropTableIfExists('{{%passwordpolicy_blocklist}}');
        $this->dropTableIfExists('{{%passwordpolicy_audit_log}}');
        $this->dropTableIfExists('{{%passwordpolicy_password_history}}');

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Creates the password history table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createPasswordHistoryTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_password_history}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_password_history}}', [
            'id' => $this->primaryKey(),
            'userId' => $this->integer()->notNull(),
            'passwordHash' => $this->string()->notNull(),
            'dateCreated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_password_history}}', ['userId', 'dateCreated'], false);
        $this->addForeignKey(null, '{{%passwordpolicy_password_history}}', ['userId'], Table::USERS, ['id'], 'CASCADE', null);
    }

    /**
     * Creates the audit log table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createAuditLogTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_audit_log}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_audit_log}}', [
            'id' => $this->primaryKey(),
            'userId' => $this->integer(),
            'changedByUserId' => $this->integer(),
            'event' => $this->string()->notNull(),
            'outcome' => $this->string()->notNull()->defaultValue('success'),
            'source' => $this->string(),
            'details' => $this->json(),
            'ipHash' => $this->string(),
            'userIdentifier' => $this->string(),
            'dateCreated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_audit_log}}', ['userId'], false);
        $this->createIndex(null, '{{%passwordpolicy_audit_log}}', ['event', 'dateCreated'], false);
        $this->addForeignKey(null, '{{%passwordpolicy_audit_log}}', ['userId'], Table::USERS, ['id'], 'SET NULL', null);
        $this->addForeignKey(null, '{{%passwordpolicy_audit_log}}', ['changedByUserId'], Table::USERS, ['id'], 'SET NULL', null);
    }

    /**
     * Creates the blocklist table.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createBlocklistTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_blocklist}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_blocklist}}', [
            'id' => $this->primaryKey(),
            'word' => $this->string()->notNull(),
            'source' => $this->string()->notNull()->defaultValue('common'),
            'dateCreated' => $this->dateTime()->notNull(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_blocklist}}', ['word'], true);
    }

    /**
     * Creates the notification log table for dedup tracking.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _createNotificationLogTable(): void
    {
        if ($this->db->tableExists('{{%passwordpolicy_notification_log}}')) {
            return;
        }

        $this->createTable('{{%passwordpolicy_notification_log}}', [
            'id' => $this->primaryKey(),
            'userId' => $this->integer()->notNull(),
            'notificationType' => $this->string()->notNull(),
            'sentAt' => $this->dateTime()->notNull(),
        ]);

        $this->createIndex(null, '{{%passwordpolicy_notification_log}}', ['userId', 'notificationType', 'sentAt'], false);
        $this->addForeignKey(null, '{{%passwordpolicy_notification_log}}', ['userId'], Table::USERS, ['id'], 'CASCADE', null);
    }
}
