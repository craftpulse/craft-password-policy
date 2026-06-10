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
 * Class ApiTokenRecord
 *
 * One row per issued Bearer token for the Feature 2 read-only REST surface
 * (Enterprise). Reads from / writes to `passwordpolicy_api_tokens`. The
 * canonical write path is
 * {@see \craftpulse\passwordpolicy\services\ApiTokenService} — `issue()`
 * inserts a row, `findByToken()` resolves one by SHA-256 hash and touches
 * `lastUsedAt`, `revoke()` deletes one.
 *
 * Security: the plaintext token is NEVER persisted. Only the SHA-256
 * `tokenHash` (the unique lookup key) and a short `tokenPrefix` (first 8
 * chars, CP display) land on the row. The plaintext is shown exactly once
 * at issue time and is not recoverable afterwards.
 *
 * @property int $id
 * @property string $name
 * @property string $tokenHash
 * @property string $tokenPrefix
 * @property string|null $scopes
 * @property \DateTime|string|null $lastUsedAt
 * @property \DateTime|string|null $expiresAt
 * @property int|null $createdByUserId
 * @property \DateTime|string $dateCreated
 * @property \DateTime|string $dateUpdated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ApiTokenRecord extends ActiveRecord
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
        return '{{%passwordpolicy_api_tokens}}';
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
            [['name', 'tokenHash', 'tokenPrefix'], 'required'],
            [['createdByUserId'], 'integer'],
            [['tokenHash'], 'string', 'length' => 64],
            [['tokenPrefix'], 'string', 'max' => 16],
        ];
    }
}
