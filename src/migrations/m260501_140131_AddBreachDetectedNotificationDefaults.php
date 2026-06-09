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
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\data\EmailDefaults;

/**
 * Class m260501_140131_AddBreachDetectedNotificationDefaults
 *
 * Seeds one `breach-detected` row per enabled site in the
 * `passwordpolicy_notification_templates` table so the new HIBP-on-login Pro
 * feature has editable defaults wired the moment admins upgrade to 5.2.0
 * and reach the Notifications subnav. Reuses the same idempotent
 * insert-if-not-exists pattern as `m260430_170841_AddNotificationTemplatesTable`.
 *
 * Schema is unchanged — `breach-detected` uses the same JSON content shape
 * as `expiry-reminder` (subject, body, optional sender overrides). New
 * notification keys land here, never as schema migrations.
 *
 * Idempotent: re-running is a no-op when the rows already exist.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260501_140131_AddBreachDetectedNotificationDefaults extends Migration
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
        $sites = Craft::$app->getSites()->getAllSites();
        // UTC — `dateCreated` / `dateUpdated` are UTC columns. A bare
        // `new \DateTime()` records the site-local wall clock and skews the
        // displayed timestamps on non-UTC installs.
        $now = (new \DateTime('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $key = 'breach-detected';

        $factory = EmailDefaults::all()[$key] ?? null;

        if ($factory === null) {
            // Nothing to seed — defensive guard against re-running this
            // migration after the key gets renamed in a later release.
            return true;
        }

        $contentJson = Json::encode(call_user_func($factory));

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
        Craft::$app->getDb()->createCommand()
            ->delete(
                '{{%passwordpolicy_notification_templates}}',
                ['notificationKey' => 'breach-detected'],
            )
            ->execute();

        return true;
    }
}
