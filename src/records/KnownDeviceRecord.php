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
 * Class KnownDeviceRecord
 *
 * One row per (user, device fingerprint) seen at login. The Feature 1
 * login listener (`DeviceTrackingService::recordLogin()`) is the canonical
 * write path — it inserts a row on the first sighting of a fingerprint and
 * bumps `lastSeenAt` on every subsequent sighting. Reads from the
 * `passwordpolicy_known_devices` table.
 *
 * Privacy: the raw user-agent and raw IP are NEVER persisted. Only the
 * derived `fingerprint` (SHA-256 of UA + masked IP), the human-readable
 * `deviceLabel`, and the `maskedIp` land here — see
 * {@see \craftpulse\passwordpolicy\services\DeviceLabelService}.
 *
 * Capture is universal across editions per memory rule
 * `project_audit_capture_principle.md`.
 *
 * @property int $id
 * @property int $userId
 * @property string $fingerprint
 * @property string|null $deviceLabel
 * @property string|null $maskedIp
 * @property int|null $siteId
 * @property \DateTime|string $firstSeenAt
 * @property \DateTime|string $lastSeenAt
 * @property \DateTime|string $dateCreated
 * @property \DateTime|string $dateUpdated
 * @property string $uid
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class KnownDeviceRecord extends ActiveRecord
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
        return '{{%passwordpolicy_known_devices}}';
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
            [['userId', 'fingerprint'], 'required'],
            [['userId', 'siteId'], 'integer'],
            [['fingerprint'], 'string', 'length' => 64],
        ];
    }
}
