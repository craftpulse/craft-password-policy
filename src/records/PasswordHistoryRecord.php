<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\records;

use craft\db\ActiveRecord;

/**
 * Class PasswordHistoryRecord
 *
 * @property int $id
 * @property int $userId
 * @property int|null $changedByUserId
 * @property string $passwordHash
 * @property string $changeReason
 * @property string|null $changeSourceIp
 * @property string|null $changeUserAgent
 * @property string|null $policySnapshot
 * @property \DateTime|string $dateCreated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordHistoryRecord extends ActiveRecord
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
        return '{{%passwordpolicy_password_history}}';
    }
}
