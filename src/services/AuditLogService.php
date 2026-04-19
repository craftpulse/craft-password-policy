<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\db\Query;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\AuditLogRecord;
use DateTime;
use yii\base\Component;

/**
 * Class AuditLogService
 *
 * Records security-relevant events without storing password data.
 * Runtime-enforced detail allowlist prevents accidental PII leakage.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditLogService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Allowed keys in the details JSON column. Any key not on this list
     * is silently stripped before database insertion.
     *
     * @var string[]
     */
    private const ALLOWED_DETAIL_KEYS = [
        'deviceLabel',
        'groupId',
        'groupName',
        'reason',
        'violationType',
        'source',
        'outcome',
        'method',
        'failMode',
    ];

    // Public Methods
    // =========================================================================

    /**
     * Logs a security event to the audit log.
     *
     * Wrapped in try/catch to never block the parent operation.
     * Gated on Enterprise edition.
     *
     * @param int|null $userId
     * @param string $event
     * @param array|null $details
     * @param string $outcome
     * @param string|null $source
     * @param int|null $changedByUserId
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function logEvent(
        ?int $userId,
        string $event,
        ?array $details = null,
        string $outcome = 'success',
        ?string $source = null,
        ?int $changedByUserId = null,
    ): void {
        // Gate on Enterprise edition
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            return;
        }

        $settings = PasswordPolicy::$plugin->getSettings();

        if (!$settings->enableAuditLog) {
            return;
        }

        try {
            // Runtime-enforced detail allowlist
            $filteredDetails = null;
            if ($details !== null) {
                $filteredDetails = array_intersect_key(
                    $details,
                    array_flip(self::ALLOWED_DETAIL_KEYS),
                );

                if (empty($filteredDetails)) {
                    $filteredDetails = null;
                }
            }

            // Determine source if not provided
            if ($source === null) {
                $source = $this->_detectSource();
            }

            // Hash IP address (never store raw)
            $ipHash = null;
            $request = Craft::$app->getRequest();
            if (!$request->getIsConsoleRequest()) {
                $ip = $request->getUserIP();
                if ($ip !== null) {
                    $ipHash = hash('sha256', $ip);
                }
            }

            // HMAC user identifier for post-deletion correlation
            $userIdentifier = null;
            if ($userId !== null) {
                $userIdentifier = $this->_hashUserIdentifier($userId);
            }

            $record = new AuditLogRecord();
            $record->userId = $userId;
            $record->changedByUserId = $changedByUserId ?? $this->_getCurrentAdminId();
            $record->event = $event;
            $record->outcome = $outcome;
            $record->source = $source;
            $record->details = $filteredDetails;
            $record->ipHash = $ipHash;
            $record->userIdentifier = $userIdentifier;
            $record->dateCreated = new DateTime();
            $record->uid = StringHelper::UUID();
            $record->save(false);
        } catch (\Throwable $e) {
            // Never block the parent operation
            Craft::error(
                'Failed to write audit log: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Returns audit log entries for a specific user.
     *
     * @param int $userId
     * @param int $limit
     * @return array
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEventsForUser(int $userId, int $limit = 50): array
    {
        return (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['userId' => $userId])
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit($limit)
            ->all();
    }

    /**
     * Returns recent audit log entries with optional event filter.
     *
     * @param int $limit
     * @param string|null $eventFilter
     * @return array
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getRecentEvents(int $limit = 100, ?string $eventFilter = null): array
    {
        $query = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit($limit);

        if ($eventFilter !== null) {
            $query->andWhere(['event' => $eventFilter]);
        }

        return $query->all();
    }

    /**
     * Purges audit log entries older than the specified number of days.
     *
     * @param int $daysToKeep
     * @return int The number of entries purged
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function purgeOldEntries(int $daysToKeep = 365): int
    {
        $threshold = (new DateTime())->modify("-{$daysToKeep} days")->format('Y-m-d H:i:s');

        return Craft::$app->getDb()->createCommand()
            ->delete('{{%passwordpolicy_audit_log}}', ['<', 'dateCreated', $threshold])
            ->execute();
    }

    // Private Methods
    // =========================================================================

    /**
     * Detects the source context for the current operation.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _detectSource(): string
    {
        if (Craft::$app->getRequest()->getIsConsoleRequest()) {
            return 'cli';
        }

        /** @var \craft\elements\User|null $currentUser */
        $currentUser = Craft::$app->getUser()->getIdentity();

        if ($currentUser !== null && $currentUser->admin) {
            return 'admin';
        }

        return 'self-service';
    }

    /**
     * Returns the current admin's user ID if in an admin context.
     *
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getCurrentAdminId(): ?int
    {
        if (Craft::$app->getRequest()->getIsConsoleRequest()) {
            return null;
        }

        /** @var \craft\elements\User|null $currentUser */
        $currentUser = Craft::$app->getUser()->getIdentity();

        return $currentUser?->id;
    }

    /**
     * Creates an HMAC-SHA-256 hash of the user's email for post-deletion correlation.
     *
     * Uses a server-side secret key. The key can be destroyed to make
     * correlation permanently impossible on demand.
     *
     * @param int $userId
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hashUserIdentifier(int $userId): ?string
    {
        $user = Craft::$app->getUsers()->getUserById($userId);

        if ($user === null || $user->email === null) {
            return null;
        }

        // Use Craft's security key as the HMAC secret
        $key = Craft::$app->getConfig()->getGeneral()->securityKey;

        return hash_hmac('sha256', $user->email, $key);
    }
}
