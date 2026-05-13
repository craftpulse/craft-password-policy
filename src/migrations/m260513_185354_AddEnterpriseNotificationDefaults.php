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
 * Class m260513_185354_AddEnterpriseNotificationDefaults
 *
 * Seeds one row per (`new-device-alert`, site) and one row per
 * (`admin-security-alert`, site) in `passwordpolicy_notification_templates`
 * so the G12 conversion of these two keys from the `composeFromKey()`
 * mailer-templates path onto the editable-templates surface has rendered
 * defaults the moment admins upgrade and the first new-device or admin
 * security event fires.
 *
 * Mirrors the idempotent insert-if-not-exists pattern from
 * `m260501_140131_AddBreachDetectedNotificationDefaults` and
 * `Install::_seedNotificationTemplateDefaults()` — same shape, same JSON
 * `content` column, same UUID + timestamp columns. Re-running is a no-op
 * when the rows already exist.
 *
 * No schema change. `PasswordPolicy::$schemaVersion` stays at `2.11.0`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260513_185354_AddEnterpriseNotificationDefaults extends Migration
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
        $now = (new \DateTime())->format('Y-m-d H:i:s');
        $keys = ['new-device-alert', 'admin-security-alert'];

        $defaults = EmailDefaults::all();

        foreach ($keys as $key) {
            $factory = $defaults[$key] ?? null;

            if ($factory === null) {
                // Defensive guard: the registry should always contain
                // both keys after this commit, but a future rename would
                // leave us seeding nothing rather than fatally erroring.
                continue;
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
        // Pragmatic: drops both keys unconditionally — `safeDown` for a
        // 5.2.0 seed migration is rarely run, and the documented rollback
        // is "uninstall + reinstall". An admin who has hand-edited their
        // templates and wants them preserved should back the rows up
        // before invoking the down-migration.
        Craft::$app->getDb()->createCommand()
            ->delete(
                '{{%passwordpolicy_notification_templates}}',
                ['notificationKey' => ['new-device-alert', 'admin-security-alert']],
            )
            ->execute();

        return true;
    }
}
