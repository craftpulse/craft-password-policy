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
use craft\records\Element;
use yii\db\ActiveQueryInterface;

/**
 * Class NotificationLogRecord
 *
 * Active-record wrapper around `passwordpolicy_notification_log`. The
 * table is element-backed (Craft 5 idiom): `id` is a FK to
 * `craft_elements.id` with `ON DELETE CASCADE`. The record stays the
 * storage layer; the queryable + index surface lives on
 * {@see \craftpulse\passwordpolicy\elements\NotificationLogElement}.
 *
 * `userId` flips to nullable + `SET NULL` so notification history
 * outlives the user, per `project_audit_capture_principle.md`.
 *
 * Datetime columns come back as raw strings — memory gap #10. Callers
 * that need real `DateTime` instances should hydrate via
 * `\craft\helpers\DateTimeHelper::toDateTime()`.
 *
 * @property int $id matches `craft_elements.id`
 * @property ?int $userId nullable since 5.2.0 — `SET NULL` on user hard-delete
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
     * Relation back to the paired `craft_elements` row.
     *
     * @return ActiveQueryInterface
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getElement(): ActiveQueryInterface
    {
        return $this->hasOne(Element::class, ['id' => 'id']);
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
