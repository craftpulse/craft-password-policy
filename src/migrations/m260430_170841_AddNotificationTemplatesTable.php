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

use Craft;
use craft\db\Migration;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\data\EmailDefaults;

/**
 * Class m260430_170841_AddNotificationTemplatesTable
 *
 * Adds the `passwordpolicy_notification_templates` table — one row per
 * (notificationKey, siteId) combination, with a JSON `content` column
 * holding subject/body/sender overrides. Mirrors Craft 5's element content
 * shape (one row per element-site with a JSON content column) so per-site
 * editing is race-free, audit-traceable, and cascade-deletes with the site.
 *
 * Eager-seeds one row per (key × enabled site) using EmailDefaults so the
 * runtime never has to fall back to translation files when looking up a
 * template.
 *
 * Idempotent: re-running is a no-op (table existence guarded;
 * (notificationKey, siteId) uniqueness guarded).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260430_170841_AddNotificationTemplatesTable extends Migration
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
        if (!$this->db->tableExists('{{%passwordpolicy_notification_templates}}')) {
            $this->createTable('{{%passwordpolicy_notification_templates}}', [
                'id' => $this->primaryKey(),
                'notificationKey' => $this->string(64)->notNull(),
                'siteId' => $this->integer()->notNull(),
                'content' => $this->json()->notNull(),
                'dateCreated' => $this->dateTime()->notNull(),
                'dateUpdated' => $this->dateTime()->notNull(),
                'uid' => $this->uid(),
            ]);

            $this->createIndex(
                null,
                '{{%passwordpolicy_notification_templates}}',
                ['notificationKey', 'siteId'],
                true,
            );
            $this->createIndex(
                null,
                '{{%passwordpolicy_notification_templates}}',
                ['siteId'],
                false,
            );
            $this->addForeignKey(
                null,
                '{{%passwordpolicy_notification_templates}}',
                ['siteId'],
                Table::SITES,
                ['id'],
                'CASCADE',
                null,
            );
        }

        $this->_seedDefaults();

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
        $this->dropTableIfExists('{{%passwordpolicy_notification_templates}}');

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * Seeds one row per (notificationKey × enabled site) using the bundled
     * defaults. Skips rows that already exist so this is safe to re-run.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _seedDefaults(): void
    {
        $sites = Craft::$app->getSites()->getAllSites();
        // UTC — `dateCreated` / `dateUpdated` are UTC columns. A bare
        // `new \DateTime()` records the site-local wall clock and skews the
        // displayed timestamps on non-UTC installs.
        $now = (new \DateTime('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        foreach (EmailDefaults::all() as $key => $factory) {
            $content = call_user_func($factory);
            $contentJson = Json::encode($content);

            foreach ($sites as $site) {
                $exists = (new Query())
                    ->from('{{%passwordpolicy_notification_templates}}')
                    ->where([
                        'notificationKey' => $key,
                        'siteId' => $site->id,
                    ])
                    ->exists();

                if ($exists) {
                    continue;
                }

                $this->insert('{{%passwordpolicy_notification_templates}}', [
                    'notificationKey' => $key,
                    'siteId' => $site->id,
                    'content' => $contentJson,
                    'dateCreated' => $now,
                    'dateUpdated' => $now,
                    'uid' => StringHelper::UUID(),
                ]);
            }
        }
    }
}
