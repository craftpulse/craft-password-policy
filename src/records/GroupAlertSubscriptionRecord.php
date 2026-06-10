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

/**
 * Class GroupAlertSubscriptionRecord
 *
 * One row per (group, event, recipient) routing rule. Feature 3 (per-group
 * alerts, Pro) reads enabled subscriptions for the affected user's RESOLVED
 * group set at alert time and routes a copy of the `breach_detected` /
 * `new_device` alert to each distinct recipient — see
 * {@see \craftpulse\passwordpolicy\services\GroupAlertService}.
 *
 * `groupId` FKs to `usergroups.id` with `ON DELETE CASCADE`: deleting a user
 * group removes its alert subscriptions automatically, so there is no
 * orphan-recipient cleanup to perform. Storage is edition-independent; the
 * dispatch that reads these rows is Pro-gated one layer up.
 *
 * @property int $id
 * @property int $groupId
 * @property string $eventType
 * @property string $recipientEmail
 * @property bool $enabled
 * @property \DateTime|string $dateCreated
 * @property \DateTime|string $dateUpdated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GroupAlertSubscriptionRecord extends ActiveRecord
{
    // Static Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function tableName(): string
    {
        return '{{%passwordpolicy_group_alert_subscriptions}}';
    }

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @return array<int, array<int, mixed>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function rules(): array
    {
        return [
            [['groupId', 'eventType', 'recipientEmail'], 'required'],
            [['groupId'], 'integer'],
            [['recipientEmail'], 'email'],
            [['enabled'], 'boolean'],
        ];
    }
}
