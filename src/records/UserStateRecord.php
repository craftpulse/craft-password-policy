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
use craftpulse\passwordpolicy\enums\ChangeReason;

/**
 * Class UserStateRecord
 *
 * One sparsely-populated row per user. Tracks pending-reset reasons +
 * breach detection state. Reads from the `passwordpolicy_user_state`
 * table; the application layer (`UserStateService`) is the canonical
 * write path.
 *
 * `pendingResetReason` is constrained at the DB level (MySQL `ENUM`,
 * PostgreSQL `CHECK IN (...)`); the rule below is the application-layer
 * mirror so save errors surface as model validation messages instead of
 * SQL exceptions on SQLite (which has no constraint).
 *
 * @property int $userId
 * @property string|null $pendingResetReason
 * @property \DateTime|string|null $pendingResetSetAt
 * @property \DateTime|string|null $lastBreachDetectedAt
 * @property \DateTime|string|null $lastBreachCheckAt
 * @property \DateTime|string $dateCreated
 * @property \DateTime|string $dateUpdated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserStateRecord extends ActiveRecord
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
        return '{{%passwordpolicy_user_state}}';
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
            [['userId'], 'required'],
            [['userId'], 'integer'],
            [['pendingResetReason'], 'in', 'range' => ChangeReason::values(), 'strict' => true],
        ];
    }
}
