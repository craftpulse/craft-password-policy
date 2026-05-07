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
 * Class AuditLogRecord
 *
 * @property int $id
 * @property int|null $userId
 * @property int|null $changedByUserId
 * @property string $event
 * @property string $outcome
 * @property string|null $source
 * @property array|null $details
 * @property string|null $ipHash
 * @property string|null $userIdentifier
 * @property string $rowHash
 * @property string $previousHash
 * @property \DateTime|null $forwardedAt
 * @property int $forwardAttempts
 * @property \DateTime $dateCreated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditLogRecord extends ActiveRecord
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
        return '{{%passwordpolicy_audit_log}}';
    }
}
