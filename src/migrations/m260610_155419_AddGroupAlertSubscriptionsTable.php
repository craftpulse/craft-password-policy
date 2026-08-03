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

/**
 * m260610_155419_AddGroupAlertSubscriptionsTable migration.
 *
 * Adds `passwordpolicy_group_alert_subscriptions` to sites already past 5.0
 * (fresh installs get it from
 * {@see Install::_createGroupAlertSubscriptionsTable()}). Backs Feature 3
 * per-group alerts (Pro) — one row per (group, event, recipient) routing
 * rule. When a user triggers a `breach_detected` / `new_device` alert, a
 * copy is routed to each enabled subscription whose `groupId` is in the
 * user's RESOLVED group set (per `project_per_group_resolution_hazard.md`).
 *
 * `groupId` FKs to `usergroups.id` with `ON DELETE CASCADE` so deleting a
 * user group removes its alert subscriptions automatically. Capture/storage
 * is edition-independent; the dispatch that reads these rows is Pro-gated.
 *
 * Idempotent — guarded by `tableExists()` so a re-run on a fully-applied
 * site is a no-op. Mirror of
 * `Install::_createGroupAlertSubscriptionsTable()`; the two are kept in
 * lockstep so fresh installs and upgraders land on identical schema without
 * depending on each other.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260610_155419_AddGroupAlertSubscriptionsTable extends Migration
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
        $table = '{{%passwordpolicy_group_alert_subscriptions}}';

        if ($this->db->tableExists($table)) {
            return true;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'groupId' => $this->integer()->notNull(),
            'eventType' => $this->string()->notNull(),
            'recipientEmail' => $this->string()->notNull(),
            'enabled' => $this->boolean()->notNull()->defaultValue(true),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        $this->createIndex(null, $table, ['groupId', 'eventType'], false);
        $this->addForeignKey(null, $table, ['groupId'], '{{%usergroups}}', ['id'], 'CASCADE', null);

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
        $this->dropTableIfExists('{{%passwordpolicy_group_alert_subscriptions}}');

        return true;
    }
}
