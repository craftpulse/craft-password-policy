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
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\data\EmailDefaults;

/**
 * Class m260610_170436_AddInactiveAccountNotificationDefaults
 *
 * Seeds one row per (`inactive-account`, site) in
 * `passwordpolicy_notification_templates` so the Feature 5 (Pro) scan's
 * `notify` mode has a rendered default the moment admins upgrade and the
 * first dormant-user notification fires. Without the seed row,
 * `NotificationService::_dispatch()` writes a `status = failed` row instead
 * of sending.
 *
 * Mirrors the idempotent insert-if-not-exists pattern from
 * `m260513_185354_AddEnterpriseNotificationDefaults` and
 * `Install::_seedNotificationTemplateDefaults()` — same shape, same JSON
 * `content` column, same UUID + timestamp columns. Re-running is a no-op
 * when the rows already exist. Fresh installs seed the key automatically
 * via `Install::_seedNotificationTemplateDefaults()` (it reads
 * `EmailDefaults::all()`), so this migration only matters for upgraders.
 *
 * No schema change. `PasswordPolicy::$schemaVersion` stays at `2.15.0`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260610_170436_AddInactiveAccountNotificationDefaults extends Migration
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
        $key = 'inactive-account';

        $factory = EmailDefaults::all()[$key] ?? null;

        if ($factory === null) {
            // Defensive guard: the registry should always contain the key
            // after this commit, but a future rename would leave us
            // seeding nothing rather than fatally erroring.
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
        // Pragmatic: drops the key unconditionally — `safeDown` for a
        // 5.2.0 seed migration is rarely run, and the documented rollback
        // is "uninstall + reinstall". An admin who has hand-edited their
        // template and wants it preserved should back the row up before
        // invoking the down-migration.
        Craft::$app->getDb()->createCommand()
            ->delete(
                '{{%passwordpolicy_notification_templates}}',
                ['notificationKey' => 'inactive-account'],
            )
            ->execute();

        return true;
    }
}
