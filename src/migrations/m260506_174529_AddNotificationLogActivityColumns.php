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
 * Class m260506_174529_AddNotificationLogActivityColumns
 *
 * Promotes `passwordpolicy_notification_log` from a server-side dedup
 * substrate (4 columns: `id`, `userId`, `notificationType`, `sentAt`)
 * into a real audit / activity table. Adds:
 *
 *  - `status` — `varchar(16)` NOT NULL default `sent`. Backed by the
 *    `NotificationStatus` PHP enum (`sent` / `failed`). Default lets
 *    legacy rows backfill to `sent` cleanly — they were only written
 *    on send-success.
 *  - `recipientEmail` — nullable `varchar`. Captures the address the
 *    mail actually went to. NULL on legacy rows; new rows always
 *    populated when the user has an email at send time.
 *  - `siteId` — nullable `int`, FK to `sites.id` ON DELETE SET NULL.
 *    Captures which site's template rendered the notification (the
 *    service resolves the site from the user's preferred language).
 *  - `subject` — nullable `text`. Rendered Twig output of the
 *    template's subject line. Stored fresh per send.
 *  - `body` — nullable `mediumtext`. Rendered Twig output of the
 *    template's body. Stored for full audit replay; operators own
 *    the content (breach-detected / expiry-reminder are plugin-
 *    authored, not user input). A future setting can opt out of body
 *    storage for storage-sensitive installs.
 *  - `errorMessage` — nullable `text`. Captures `Throwable::getMessage()`
 *    on the failure path. Privacy-safe — synchronous mailer + Twig
 *    exceptions never carry password material.
 *  - `resentFromId` — nullable `int`, self-FK to
 *    `passwordpolicy_notification_log.id` ON DELETE SET NULL. Links
 *    a re-sent row back to its origin so the activity index can
 *    surface the chain.
 *
 * Idempotent — every column add is guarded by `columnExists()`.
 * Re-running on a half-applied DB is a no-op per column.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260506_174529_AddNotificationLogActivityColumns extends Migration
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
        $table = '{{%passwordpolicy_notification_log}}';

        if (!$this->db->columnExists($table, 'status')) {
            $this->addColumn(
                $table,
                'status',
                $this->string(16)->notNull()->defaultValue('sent')->after('notificationType'),
            );

            // Composite index for the Activity index page's most common
            // filter — status + sentAt — so paginated reads on the new
            // surface don't full-scan the table once it grows. Nested
            // here (rather than at the bottom of safeUp()) so re-running
            // the migration on a fully-applied DB doesn't try to create
            // a duplicate index — same idempotency idiom the per-column
            // FK / index pairs further down use.
            $this->createIndex(null, $table, ['status', 'sentAt'], false);
        }

        if (!$this->db->columnExists($table, 'recipientEmail')) {
            $this->addColumn(
                $table,
                'recipientEmail',
                $this->string()->null()->after('status'),
            );
        }

        if (!$this->db->columnExists($table, 'siteId')) {
            $this->addColumn(
                $table,
                'siteId',
                $this->integer()->null()->after('recipientEmail'),
            );
            $this->createIndex(null, $table, ['siteId'], false);
            $this->addForeignKey(
                null,
                $table,
                ['siteId'],
                Table::SITES,
                ['id'],
                'SET NULL',
                null,
            );
        }

        if (!$this->db->columnExists($table, 'subject')) {
            $this->addColumn(
                $table,
                'subject',
                $this->text()->null()->after('siteId'),
            );
        }

        if (!$this->db->columnExists($table, 'body')) {
            $this->addColumn(
                $table,
                'body',
                $this->mediumText()->null()->after('subject'),
            );
        }

        if (!$this->db->columnExists($table, 'errorMessage')) {
            $this->addColumn(
                $table,
                'errorMessage',
                $this->text()->null()->after('body'),
            );
        }

        if (!$this->db->columnExists($table, 'resentFromId')) {
            $this->addColumn(
                $table,
                'resentFromId',
                $this->integer()->null()->after('errorMessage'),
            );
            $this->createIndex(null, $table, ['resentFromId'], false);
            $this->addForeignKey(
                null,
                $table,
                ['resentFromId'],
                $table,
                ['id'],
                'SET NULL',
                null,
            );
        }

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
        echo "m260506_174529_AddNotificationLogActivityColumns cannot be reverted.\n";

        return false;
    }
}
