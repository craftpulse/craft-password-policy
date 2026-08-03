<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Carbon\Carbon;
use Craft;
use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\models\KnownDeviceModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\KnownDeviceRecord;
use yii\base\Component;

/**
 * Class DeviceTrackingService
 *
 * Owns the `passwordpolicy_known_devices` write + read path for Feature 1.
 * The login listener calls {@see recordLogin()} on
 * `yii\web\User::EVENT_AFTER_LOGIN`; the method derives a stable device
 * fingerprint, upserts the row, and reports whether the device was new so
 * the listener can decide whether to fire the (Enterprise-gated)
 * new-device alert.
 *
 * **Capture is universal** across editions per memory rule
 * `project_audit_capture_principle.md` — `recordLogin()` writes a row on
 * Lite / Pro / Enterprise alike. There is NO edition gate in this service;
 * the gate lives on the alert email + audit-log exposure one layer up. An
 * Enterprise upgrade therefore inherits a populated device history rather
 * than starting blank.
 *
 * **Privacy.** The raw user-agent and raw IP are NEVER persisted. The
 * fingerprint is a SHA-256 of the user-agent + the MASKED IP, and only the
 * derived `deviceLabel` + `maskedIp` land on the row (see `security.md`
 * and {@see DeviceLabelService}).
 *
 * Date handling: `Carbon` (service layer) for the timestamps written to /
 * compared against the table — never `DateTimeHelper` here, per the
 * "DateTimeHelper in elements/queries, Carbon in services" split.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class DeviceTrackingService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Computes the stable fingerprint for a (user-agent, masked-IP) pair.
     * SHA-256 over `"{userAgent}|{maskedIp}"`. Public so the listener +
     * tests can derive the same value the row is keyed on.
     *
     * The IP is masked BEFORE hashing so two logins from adjacent
     * addresses in the same /24 (IPv4) or /64 (IPv6) collapse to one
     * device — a dynamic-IP user on the same network isn't re-alerted on
     * every DHCP lease change.
     *
     * @param string $userAgent the raw request user-agent
     * @param string $maskedIp the already-masked IP (from
     *     {@see DeviceLabelService::maskIp()})
     * @return string the 64-char hex SHA-256 fingerprint
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function fingerprint(string $userAgent, string $maskedIp): string
    {
        return hash('sha256', $userAgent . '|' . $maskedIp);
    }

    /**
     * Returns the known devices for a user, most-recently-seen first.
     *
     * @param int $userId
     * @return KnownDeviceModel[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getDevicesForUser(int $userId): array
    {
        /** @var KnownDeviceRecord[] $records */
        $records = KnownDeviceRecord::find()
            ->where(['userId' => $userId])
            ->orderBy(['lastSeenAt' => SORT_DESC])
            ->all();

        return array_map(
            static fn(KnownDeviceRecord $record): KnownDeviceModel => KnownDeviceModel::fromRecord($record),
            $records,
        );
    }

    /**
     * Prunes device rows whose `lastSeenAt` is older than the retention
     * window. Idempotent — safe to call from `gc/run` cron repeatedly.
     *
     * Capture is universal, so this runs on every edition (a Lite install
     * that's been writing device rows must still prune them or the table
     * grows unbounded). A non-positive `$retentionDays` is treated as "no
     * pruning" and returns 0 — never deletes the whole table on a
     * misconfiguration.
     *
     * @param int $retentionDays delete rows last seen more than this many
     *     days ago
     * @return int the number of rows deleted
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function pruneOldDevices(int $retentionDays): int
    {
        if ($retentionDays <= 0) {
            return 0;
        }

        $threshold = Carbon::now('UTC')->subDays($retentionDays)->format('Y-m-d H:i:s');

        return Craft::$app->getDb()->createCommand()
            ->delete(
                '{{%passwordpolicy_known_devices}}',
                ['<', 'lastSeenAt', $threshold],
            )
            ->execute();
    }

    /**
     * Records a login for device-tracking. Computes the fingerprint,
     * upserts the row, and returns whether the device was NEW (no prior
     * row for this `(userId, fingerprint)`):
     *
     *  - New device → inserts a row with `firstSeenAt = lastSeenAt = now`
     *    and returns `true`.
     *  - Known device → bumps `lastSeenAt = now` and returns `false`.
     *
     * Capture is universal — this writes on every edition. The caller
     * decides (on Enterprise + `enableNewDeviceAlerts`) whether to act on
     * a `true` return by firing the alert email; the row itself is
     * written regardless.
     *
     * Privacy: `$userAgent` + `$rawIp` are used only to derive the
     * fingerprint, label, and masked IP. Neither raw value is persisted.
     *
     * @param User $user the authenticated user
     * @param string $userAgent the raw request user-agent
     * @param string $rawIp the raw request IP (masked before storage)
     * @param int|null $siteId the site the login happened on, or null
     * @return bool true when the device was newly recorded, false when it
     *     was already known
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recordLogin(User $user, string $userAgent, string $rawIp, ?int $siteId): bool
    {
        $labelService = PasswordPolicy::$plugin->getDeviceLabel();
        $maskedIp = $labelService->maskIp($rawIp);
        $fingerprint = $this->fingerprint($userAgent, $maskedIp);

        $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

        $existing = KnownDeviceRecord::findOne([
            'userId' => $user->id,
            'fingerprint' => $fingerprint,
        ]);

        if ($existing !== null) {
            $existing->lastSeenAt = $now;
            $existing->dateUpdated = $now;
            $existing->save(false);

            return false;
        }

        $record = new KnownDeviceRecord();
        $record->userId = (int)$user->id;
        $record->fingerprint = $fingerprint;
        $record->deviceLabel = $labelService->label($userAgent);
        $record->maskedIp = $maskedIp;
        $record->siteId = $siteId;
        $record->firstSeenAt = $now;
        $record->lastSeenAt = $now;
        $record->dateCreated = $now;
        $record->dateUpdated = $now;
        $record->uid = StringHelper::UUID();
        $record->save(false);

        return true;
    }
}
