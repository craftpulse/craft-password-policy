<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\records;

use craft\db\ActiveRecord;
use yii\db\ActiveQueryInterface;

/**
 * Class NotificationLogRecord
 *
 * Active-record wrapper around `passwordpolicy_notification_log`. The
 * table doubles as both the dedup substrate (`_hasRecentNotification`
 * filters on `status = 'sent'`) and the user-facing activity log
 * (read paths in `NotificationActivityService`).
 *
 * Datetime columns come back as raw strings — memory gap #10. Callers
 * that need real `DateTime` instances should hydrate via
 * `\craft\helpers\DateTimeHelper::toDateTime()`.
 *
 * @property int $id
 * @property int $userId
 * @property string $notificationType
 * @property string $status `sent` / `failed` — backed by {@see \craftpulse\passwordpolicy\enums\NotificationStatus}
 * @property ?string $recipientEmail address the message went to (null on legacy rows)
 * @property ?int $siteId site whose template rendered (null on legacy rows or after site soft-delete)
 * @property ?string $subject rendered Twig output of the template's subject
 * @property ?string $body rendered Twig output of the template's body
 * @property ?string $errorMessage `Throwable::getMessage()` on the failure path
 * @property ?int $resentFromId self-FK pointing at the row this is a re-send of
 * @property string $sentAt
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationLogRecord extends ActiveRecord
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function tableName(): string
    {
        return '{{%passwordpolicy_notification_log}}';
    }

    /**
     * Relation to the originating row when this record is a re-send.
     * Returns null when the row was an original send. Useful for
     * walking the resend chain in the activity detail view.
     *
     * @return ActiveQueryInterface
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getResentFrom(): ActiveQueryInterface
    {
        return $this->hasOne(self::class, ['id' => 'resentFromId']);
    }
}
