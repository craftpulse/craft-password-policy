<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\helpers\Db;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\data\EmailDefaults;
use craftpulse\passwordpolicy\models\NotificationTemplateModel;
use craftpulse\passwordpolicy\records\NotificationTemplateRecord;
use Throwable;
use yii\base\Component;
use yii\db\Exception;

/**
 * Class NotificationTemplateService
 *
 * CRUD layer for the per-(notificationKey, siteId) email templates that
 * back the Pro Email Notifications UI. Mirrors PolicyService in shape but
 * tied to the JSON-content storage idiom (one row per (key, site) with a
 * `content` blob).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationTemplateService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the template for a given (notificationKey, siteId) pair.
     *
     * Falls back to the primary site's row when no exact match exists —
     * this only kicks in for callers that pass a non-existent siteId
     * (the install migration + site propagation listener keep one row per
     * (key, site) for every enabled site, so the fallback is a defensive
     * safety net rather than a hot path).
     *
     * @param string $key the notification key (e.g. `expiry-reminder`)
     * @param int $siteId the target site ID
     * @return NotificationTemplateModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTemplate(string $key, int $siteId): ?NotificationTemplateModel
    {
        $record = NotificationTemplateRecord::findOne([
            'notificationKey' => $key,
            'siteId' => $siteId,
        ]);

        if ($record === null) {
            $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

            if ($siteId === $primarySiteId) {
                return null;
            }

            $record = NotificationTemplateRecord::findOne([
                'notificationKey' => $key,
                'siteId' => $primarySiteId,
            ]);
        }

        return $record !== null ? NotificationTemplateModel::fromRecord($record) : null;
    }

    /**
     * Returns every template row for a given notification key across all
     * sites, hydrated as models. Used for the index "sites with overrides"
     * count.
     *
     * @param string $key the notification key
     * @return NotificationTemplateModel[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAllForKey(string $key): array
    {
        $records = NotificationTemplateRecord::find()
            ->where(['notificationKey' => $key])
            ->all();

        return array_map(
            fn(NotificationTemplateRecord $record) => NotificationTemplateModel::fromRecord($record),
            $records,
        );
    }

    /**
     * Saves a template, validating first. Upserts on (notificationKey, siteId).
     *
     * @param NotificationTemplateModel $model the template to save
     * @return bool whether the save succeeded
     *
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function saveTemplate(NotificationTemplateModel $model): bool
    {
        if (!$model->validate()) {
            return false;
        }

        $record = $model->id !== null
            ? NotificationTemplateRecord::findOne(['id' => $model->id])
            : NotificationTemplateRecord::findOne([
                'notificationKey' => $model->notificationKey,
                'siteId' => $model->siteId,
            ]);

        if ($record === null) {
            $record = new NotificationTemplateRecord();
            $record->notificationKey = $model->notificationKey;
            $record->siteId = $model->siteId;
            $record->uid = $model->uid ?? StringHelper::UUID();
        }

        $record->content = Json::encode($model->toContentJson());

        if (!$record->save()) {
            return false;
        }

        $model->id = (int)$record->id;
        $model->uid = $record->uid;

        return true;
    }

    /**
     * Propagates the primary-site rows for every known notification key
     * onto a newly-added site, skipping rows that already exist.
     *
     * @param int $siteId the new site's ID
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function propagateToSite(int $siteId): void
    {
        $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

        if ($siteId === $primarySiteId) {
            return;
        }

        // `dateCreated` / `dateUpdated` are UTC-convention columns (Craft's
        // standard datetime column contract). A bare
        // `(new \DateTime())->format(...)` writes the ambient process wall
        // clock (`system.timeZone`) into them raw, skewing the stored value
        // by the full UTC offset on any non-UTC install.
        // `Db::prepareDateForDb()` converts to UTC before formatting.
        $now = Db::prepareDateForDb(new \DateTime());

        foreach (array_keys(EmailDefaults::all()) as $key) {
            $exists = NotificationTemplateRecord::find()
                ->where(['notificationKey' => $key, 'siteId' => $siteId])
                ->exists();

            if ($exists) {
                continue;
            }

            $primary = NotificationTemplateRecord::findOne([
                'notificationKey' => $key,
                'siteId' => $primarySiteId,
            ]);

            $contentJson = $primary !== null
                ? $primary->content
                : Json::encode(call_user_func(EmailDefaults::all()[$key]));

            Craft::$app->getDb()->createCommand()
                ->insert('{{%passwordpolicy_notification_templates}}', [
                    'notificationKey' => $key,
                    'siteId' => $siteId,
                    'content' => $contentJson,
                    'dateCreated' => $now,
                    'dateUpdated' => $now,
                    'uid' => StringHelper::UUID(),
                ])
                ->execute();
        }
    }
}
