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
     * @param int $userId
     * @param string $passwordHash
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function savePasswordHash(int $userId, string $passwordHash): void
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        $record = new PasswordHistoryRecord();
        $record->userId = $userId;
        $record->passwordHash = $passwordHash;
        $record->dateCreated = new \DateTime();
        $record->uid = StringHelper::UUID();
        $record->save(false);

        // Prune history within the same operation
        $this->pruneHistory(
            $userId,
            $settings->passwordHistoryCount,
            $settings->passwordHistoryExpiryDays,
        );
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

        // Constant-time comparison — no early break
        $found = false;
        $iterations = 0;

        foreach ($hashes as $hash) {
            if (password_verify($plaintext, $hash)) {
                $found = true;
            }
            $iterations++;
        }

        // Pad iterations to configured limit for consistent timing
        $dummyHash = '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012';
        while ($iterations < $limit) {
            password_verify($plaintext, $dummyHash);
            $iterations++;
        }

        return $found;
    }

    /**
     * Prunes password history entries beyond the configured limits.
     *
     * @param int $userId
     * @param int $keepCount
     * @param int $expiryDays
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function pruneHistory(int $userId, int $keepCount, int $expiryDays): void
    {
        // Prune by count: keep only the most recent N entries
        if ($keepCount > 0) {
            $keepIds = (new Query())
                ->select(['id'])
                ->from('{{%passwordpolicy_password_history}}')
                ->where(['userId' => $userId])
                ->orderBy(['dateCreated' => SORT_DESC])
                ->limit($keepCount)
                ->column();

            if (!empty($keepIds)) {
                Craft::$app->getDb()->createCommand()
                    ->delete('{{%passwordpolicy_password_history}}', [
                        'and',
                        ['userId' => $userId],
                        ['not in', 'id', $keepIds],
                    ])
                    ->execute();
            }
        }

        // Prune by age
        if ($expiryDays > 0) {
            $threshold = (new \DateTime())->modify("-{$expiryDays} days")->format('Y-m-d H:i:s');

            Craft::$app->getDb()->createCommand()
                ->delete('{{%passwordpolicy_password_history}}', [
                    'and',
                    ['userId' => $userId],
                    ['<', 'dateCreated', $threshold],
                ])
                ->execute();
        }
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
