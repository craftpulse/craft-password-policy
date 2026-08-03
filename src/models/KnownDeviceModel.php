<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use craft\base\Model;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\records\KnownDeviceRecord;
use DateTime;

/**
 * Class KnownDeviceModel
 *
 * Transport model for a row in `passwordpolicy_known_devices`. Pairs with
 * {@see KnownDeviceRecord} — the read surfaces
 * ({@see \craftpulse\passwordpolicy\services\DeviceTrackingService::getDevicesForUser()})
 * hydrate models from records so callers never touch ActiveRecord
 * datetime-string quirks.
 *
 * Datetime columns come back from ActiveRecord as raw strings;
 * `fromRecord()` hydrates them via `DateTimeHelper::toDateTime()` per the
 * project idiom (direct assignment to `?DateTime` properties throws on a
 * string).
 *
 * Edition: every — the model class itself is edition-independent (capture
 * is universal). The new-device alert email + audit-log exposure that read
 * the same data are Enterprise-gated one layer up.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class KnownDeviceModel extends Model
{
    // Static Methods
    // =========================================================================

    /**
     * Builds a model from a record, hydrating datetime strings into
     * `?DateTime` instances.
     *
     * @param KnownDeviceRecord $record
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromRecord(KnownDeviceRecord $record): self
    {
        $model = new self();
        $model->id = (int)$record->id;
        $model->userId = (int)$record->userId;
        $model->fingerprint = (string)$record->fingerprint;
        $model->deviceLabel = $record->deviceLabel;
        $model->maskedIp = $record->maskedIp;
        $model->siteId = $record->siteId !== null ? (int)$record->siteId : null;
        $model->firstSeenAt = DateTimeHelper::toDateTime($record->firstSeenAt) ?: null;
        $model->lastSeenAt = DateTimeHelper::toDateTime($record->lastSeenAt) ?: null;
        $model->dateCreated = DateTimeHelper::toDateTime($record->dateCreated) ?: null;
        $model->dateUpdated = DateTimeHelper::toDateTime($record->dateUpdated) ?: null;
        $model->uid = (string)$record->uid;

        return $model;
    }

    // Public Properties
    // =========================================================================

    /**
     * @var DateTime|null when the row was created.
     */
    public ?DateTime $dateCreated = null;

    /**
     * @var DateTime|null when the row was last updated.
     */
    public ?DateTime $dateUpdated = null;

    /**
     * @var string|null human-readable device label (e.g. "Chrome on
     *     macOS"), optionally suffixed with a geo hint. Never the raw
     *     user-agent.
     */
    public ?string $deviceLabel = null;

    /**
     * @var string|null SHA-256 fingerprint of the user-agent + masked IP.
     */
    public ?string $fingerprint = null;

    /**
     * @var DateTime|null when this device fingerprint was first seen.
     */
    public ?DateTime $firstSeenAt = null;

    /**
     * @var int|null primary key.
     */
    public ?int $id = null;

    /**
     * @var DateTime|null when this device fingerprint was last seen.
     */
    public ?DateTime $lastSeenAt = null;

    /**
     * @var string|null the source IP with the last IPv4 octet zeroed /
     *     IPv6 truncated to /64. Never the raw IP.
     */
    public ?string $maskedIp = null;

    /**
     * @var int|null the site the login happened on, or null.
     */
    public ?int $siteId = null;

    /**
     * @var string|null UUID.
     */
    public ?string $uid = null;

    /**
     * @var int|null the user this device belongs to.
     */
    public ?int $userId = null;
}
