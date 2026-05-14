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
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\models\AuditContext;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\PasswordHistoryRecord;
use yii\base\Component;
use yii\db\Exception;

/**
 * Class PasswordHistoryService
 *
 * Manages password history storage and reuse detection. Plaintext passwords
 * are held in a process-private static cache only during the save cycle —
 * never persisted, never logged.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordHistoryService extends Component
{
    // Private Properties
    // =========================================================================

    /**
     * Temporary in-memory cache of plaintext passwords during the save cycle.
     * Keyed by "{userId}:{spl_object_id}" to prevent cross-contamination.
     *
     * @var array<string, string>
     */
    private static array $_pendingPasswords = [];

    // Public Methods
    // =========================================================================

    /**
     * Caches a plaintext password for later history storage.
     *
     * Called from EVENT_BEFORE_SAVE. The plaintext is held in a static property
     * only during the save cycle and cleared in EVENT_AFTER_SAVE or at request end.
     *
     * @param int $userId
     * @param string $cacheKey
     * @param string $plaintext
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function cachePassword(int $userId, string $cacheKey, #[\SensitiveParameter] string $plaintext): void
    {
        // Clear any stale entry for this user first
        foreach (array_keys(self::$_pendingPasswords) as $key) {
            if (str_starts_with($key, $userId . ':')) {
                unset(self::$_pendingPasswords[$key]);
            }
        }

        self::$_pendingPasswords[$cacheKey] = $plaintext;
    }

    /**
     * Extracts and clears a cached plaintext password atomically.
     *
     * @param string $cacheKey
     * @return string|null The plaintext password, or null if not cached
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAndClearCache(string $cacheKey): ?string
    {
        if (!isset(self::$_pendingPasswords[$cacheKey])) {
            return null;
        }

        $plaintext = self::$_pendingPasswords[$cacheKey];
        unset(self::$_pendingPasswords[$cacheKey]);

        return $plaintext;
    }

    /**
     * Unconditionally clears all cached plaintext passwords.
     *
     * Safety net called at end of every request and queue job.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function clearAllCache(): void
    {
        self::$_pendingPasswords = [];
    }

    /**
     * Stores a password hash in the history table and prunes old entries.
     *
     * The `$context` parameter records audit-trail metadata — who made
     * the change, over which transport, against which policy snapshot.
     * Capture is non-negotiable across editions; gates apply to UI / API
     * exposure of the captured rows downstream, never to the write path
     * (memory rule `project_audit_capture_principle.md`). Defaults to a
     * self-service context if not supplied — Phase D1 walks every call
     * site to thread the appropriate context through; D0 only updates
     * the migration-seed call site as the proof-of-shape.
     *
     * @param int $userId
     * @param string $passwordHash
     * @param AuditContext|null $context audit metadata; defaults to
     *     `AuditContext::selfService()` for safe fallback at any unaudited
     *     call site
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function savePasswordHash(int $userId, string $passwordHash, ?AuditContext $context = null): void
    {
        $settings = PasswordPolicy::$plugin->getSettings();
        $context ??= AuditContext::selfService();

        $record = new PasswordHistoryRecord();
        $record->userId = $userId;
        $record->changedByUserId = $context->changedByUserId;
        $record->passwordHash = $passwordHash;
        $record->changeReason = $context->reason->value;
        $record->changeSourceIp = $context->sourceIp;
        $record->changeUserAgent = $context->userAgent;
        $record->policySnapshot = $context->policySnapshot;
        $record->dateCreated = \Carbon\Carbon::now('UTC');
        $record->uid = StringHelper::UUID();
        $record->save(false);

        // Prune entries beyond the count limit
        $this->pruneHistory($userId, $settings->passwordHistoryCount);
    }

    /**
     * Checks whether a plaintext password matches any stored history entry.
     *
     * Uses constant-time comparison: no early break, padded iterations to
     * the configured limit to prevent timing analysis.
     *
     * @param int $userId
     * @param string $plaintext
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isPasswordReused(int $userId, #[\SensitiveParameter] string $plaintext): bool
    {
        $settings = PasswordPolicy::$plugin->getSettings();
        $limit = $settings->passwordHistoryCount;

        if ($limit <= 0) {
            return false;
        }

        // Fetch historical hashes
        $hashes = (new Query())
            ->select(['passwordHash'])
            ->from('{{%passwordpolicy_password_history}}')
            ->where(['userId' => $userId])
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit($limit)
            ->column();

        // Also check current password in users table if history has fewer
        // entries than configured limit — covers users who haven't changed
        // their password since migration seeding
        if (count($hashes) < $limit) {
            $currentHash = (new Query())
                ->select(['password'])
                ->from(Table::USERS)
                ->where(['id' => $userId])
                ->scalar();

            if ($currentHash && !in_array($currentHash, $hashes, true)) {
                $hashes[] = $currentHash;
            }
        }

        // Constant-time comparison — no early break. Route through
        // Craft's Security service rather than `password_verify()`
        // directly so a site-level pepper (or any future Security
        // service customisation) applies uniformly across the active
        // password check and the history check — the two paths must
        // agree on hash settings or peppered hashes become silently
        // unverifiable across rotation.
        $security = Craft::$app->getSecurity();
        $found = false;
        $iterations = 0;

        foreach ($hashes as $hash) {
            if ($security->validatePassword($plaintext, $hash)) {
                $found = true;
            }
            $iterations++;
        }

        // Pad iterations to configured limit for consistent timing
        $dummyHash = '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012';
        while ($iterations < $limit) {
            $security->validatePassword($plaintext, $dummyHash);
            $iterations++;
        }

        return $found;
    }

    /**
     * Prunes password history entries beyond the configured count.
     *
     * The count is the floor — the latest N entries are always kept,
     * regardless of age. Anything beyond N is deleted. This prevents
     * the edge case where TTL wipes a user's only history entry
     * (allowing immediate reuse) when they rarely change passwords.
     *
     * Age-based cleanup (GDPR data minimization) is handled separately
     * by the GC hook, which respects the count floor across all users.
     *
     * @param int $userId
     * @param int $keepCount
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function pruneHistory(int $userId, int $keepCount): void
    {
        if ($keepCount <= 0) {
            return;
        }

        // The latest N entries are always protected
        $protectedIds = (new Query())
            ->select(['id'])
            ->from('{{%passwordpolicy_password_history}}')
            ->where(['userId' => $userId])
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit($keepCount)
            ->column();

        if (empty($protectedIds)) {
            return;
        }

        // Delete everything beyond the count
        Craft::$app->getDb()->createCommand()
            ->delete('{{%passwordpolicy_password_history}}', [
                'and',
                ['userId' => $userId],
                ['not in', 'id', $protectedIds],
            ])
            ->execute();
    }

    /**
     * Purges old password history entries across all users for GDPR
     * data minimization. Respects the history count floor — never
     * deletes entries that are within a user's configured count.
     *
     * Called from the GC hook, not from per-save pruning.
     *
     * @param int $expiryDays
     * @param int $keepCount
     * @return int The number of entries purged
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function purgeExpiredHistory(int $expiryDays, int $keepCount): int
    {
        if ($expiryDays <= 0) {
            return 0;
        }

        $threshold = \Carbon\Carbon::now('UTC')->subDays($expiryDays)->format('Y-m-d H:i:s');

        // Get all users with history entries
        $userIds = (new Query())
            ->select(['userId'])
            ->distinct()
            ->from('{{%passwordpolicy_password_history}}')
            ->column();

        $totalPurged = 0;

        foreach ($userIds as $userId) {
            // Protect the latest N entries per user
            $protectedIds = (new Query())
                ->select(['id'])
                ->from('{{%passwordpolicy_password_history}}')
                ->where(['userId' => $userId])
                ->orderBy(['dateCreated' => SORT_DESC])
                ->limit(max($keepCount, 1))
                ->column();

            // Delete entries older than TTL that are NOT in the protected set
            $totalPurged += Craft::$app->getDb()->createCommand()
                ->delete('{{%passwordpolicy_password_history}}', [
                    'and',
                    ['userId' => $userId],
                    ['not in', 'id', $protectedIds],
                    ['<', 'dateCreated', $threshold],
                ])
                ->execute();
        }

        return $totalPurged;
    }

    /**
     * Returns debug info that hides the plaintext cache from debug tools.
     *
     * @return array
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __debugInfo(): array
    {
        return [
            '_pendingCount' => count(self::$_pendingPasswords),
        ];
    }
}
