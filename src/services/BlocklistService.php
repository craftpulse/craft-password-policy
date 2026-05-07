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

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craftpulse\passwordpolicy\PasswordPolicy;
use DateTime;
use InvalidArgumentException;
use yii\base\Component;
use yii\db\Exception;

/**
 * Class BlocklistService
 *
 * Manages the common and custom password blocklist. Seeds common passwords
 * from a bundled data file, supports custom word CRUD, and provides cache
 * management for the validator.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BlocklistService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Legacy validator cache key — `[word => source]` map.
     *
     * Held by callers that pre-date the per-policy editor (G6) and read
     * the simple word→source shape. Cleared alongside the full cache.
     *
     * @var string
     */
    private const CACHE_KEY = 'passwordpolicy_blocklist_word_sources';

    /**
     * Full-table cache key — `[word => ['source' => ..., 'policyId' => ...]]`.
     *
     * Loaded once per request by `CommonPasswordValidator`, which then
     * filters in-memory against the validator's `policyIds` config. Single
     * key avoids N-policy-combination cache fragmentation; the full
     * blocklist (~10k common + custom + per-policy rows) fetches faster
     * than maintaining per-policy-set keys with their own invalidation.
     *
     * @var string
     */
    private const CACHE_KEY_FULL = 'pp:blocklist:full';

    // Public Methods
    // =========================================================================

    /**
     * Seeds the blocklist table with common passwords from the bundled data file.
     *
     * Deletes all existing 'common' source entries and re-inserts from the
     * data file. Run after plugin install and plugin updates.
     *
     * @return int The number of words seeded
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function seedCommonPasswords(): int
    {
        $dataFile = dirname(__DIR__) . '/data/common-passwords.php';

        if (!file_exists($dataFile)) {
            return 0;
        }

        $words = require $dataFile;

        if (!is_array($words)) {
            return 0;
        }

        // Delete existing common entries
        Craft::$app->getDb()->createCommand()
            ->delete('{{%passwordpolicy_blocklist}}', ['source' => 'common'])
            ->execute();

        // Batch insert new entries (deduplicated)
        $now = Carbon::now('UTC')->format('Y-m-d H:i:s');
        $rows = [];
        $seen = [];

        foreach ($words as $word) {
            $word = strtolower(trim($word));
            if (empty($word) || isset($seen[$word])) {
                continue;
            }
            $seen[$word] = true;
            $rows[] = [$word, 'common', $now];
        }

        if (!empty($rows)) {
            // Insert in chunks to avoid memory issues with large datasets
            foreach (array_chunk($rows, 1000) as $chunk) {
                Craft::$app->getDb()->createCommand()
                    ->batchInsert(
                        '{{%passwordpolicy_blocklist}}',
                        ['word', 'source', 'dateCreated'],
                        $chunk,
                    )
                    ->execute();
            }
        }

        $this->clearCache();

        return count($rows);
    }

    /**
     * Adds a custom word to the blocklist.
     *
     * `$policyId === null` (default) writes a global custom row that every
     * policy's `checkCommonPasswords` rule sees. `$policyId !== null` scopes
     * the entry to that named policy — the validator only sees it when the
     * user's resolved policy set includes that id. The `policyId` column
     * shipped in P1.11 alongside a CASCADE FK on the policies table; per-
     * policy rows are deleted automatically when the policy is removed.
     *
     * The schema enforces a single unique index on `word`, so the same
     * word can exist EITHER as a global entry OR as a per-policy entry,
     * never both. Duplicate detection runs against any existing row with
     * the same word regardless of policyId — admins who scope a word to
     * a policy and later try to add it globally see the duplicate-noop
     * return value. The `#[\SensitiveParameter]` attribute keeps `$word`
     * out of stack traces; admin-entered blocklist tokens are commonly
     * drawn from the same pool as real passwords.
     *
     * @param string $word the word to block (case-insensitive)
     * @param int|null $policyId the policy ID to scope the entry to, or null for global
     * @return bool whether the word was added (false if duplicate)
     *
     * @throws Exception
     * @throws InvalidArgumentException when `$policyId` references a non-existent policy
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function addCustomWord(#[\SensitiveParameter] string $word, ?int $policyId = null): bool
    {
        $word = strtolower(trim($word));

        if (empty($word)) {
            return false;
        }

        if ($policyId !== null && PasswordPolicy::$plugin->getPolicies()->getPolicyById($policyId) === null) {
            throw new InvalidArgumentException(
                "Cannot add custom blocklist word: policy {$policyId} does not exist.",
            );
        }

        // Word column carries a single-column unique index — `word` is
        // globally unique across every (source, policyId) combination.
        $exists = (new Query())
            ->from('{{%passwordpolicy_blocklist}}')
            ->where(['word' => $word])
            ->exists();

        if ($exists) {
            return false;
        }

        Craft::$app->getDb()->createCommand()
            ->insert('{{%passwordpolicy_blocklist}}', [
                'word' => $word,
                'source' => 'custom',
                'policyId' => $policyId,
                'dateCreated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
            ])
            ->execute();

        $this->clearCache();

        return true;
    }

    /**
     * Removes a custom word from the blocklist by ID.
     *
     * @param int $id
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function removeCustomWord(int $id): void
    {
        Craft::$app->getDb()->createCommand()
            ->delete('{{%passwordpolicy_blocklist}}', [
                'id' => $id,
                'source' => 'custom',
            ])
            ->execute();

        $this->clearCache();
    }

    /**
     * Returns paginated custom words for the settings UI.
     *
     * @param int $page
     * @param int $perPage
     * @return array{words: array, total: int}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getCustomWords(int $page = 1, int $perPage = 50): array
    {
        $query = (new Query())
            ->from('{{%passwordpolicy_blocklist}}')
            ->where(['source' => 'custom'])
            ->orderBy(['word' => SORT_ASC]);

        $total = $query->count();

        $words = $query
            ->offset(($page - 1) * $perPage)
            ->limit($perPage)
            ->all();

        return [
            'words' => $words,
            'total' => (int)$total,
        ];
    }

    /**
     * Returns every global custom blocklist row (no pagination), ordered
     * by word ASC. Used by the global EditableTable editor which renders
     * the full set on one screen for in-place editing.
     *
     * Per-policy entries (`policyId IS NOT NULL`) are excluded — they
     * belong to the per-policy editor on the policy edit screen.
     *
     * @return array<int, array<string, mixed>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAllCustomWords(): array
    {
        return (new Query())
            ->from('{{%passwordpolicy_blocklist}}')
            ->where([
                'source' => 'custom',
                'policyId' => null,
            ])
            ->orderBy(['word' => SORT_ASC])
            ->all();
    }

    /**
     * Returns the custom blocklist rows scoped to the given policy ID,
     * ordered by word ASC. Used by the Enterprise per-policy EditableTable
     * editor (G6) and by the controller's diff-on-save path to compute
     * which existing rows belong to the current edit.
     *
     * Global entries (`policyId IS NULL`) are NOT included — those are
     * managed by the top-level Blocklist subnav, not the per-policy tab.
     *
     * @param int $policyId the policy ID to scope the lookup to
     * @return array<int, array<string, mixed>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getCustomWordsForPolicy(int $policyId): array
    {
        return (new Query())
            ->from('{{%passwordpolicy_blocklist}}')
            ->where([
                'source' => 'custom',
                'policyId' => $policyId,
            ])
            ->orderBy(['word' => SORT_ASC])
            ->all();
    }

    /**
     * Returns the merged blocklist for the given policy as a `[word => source]`
     * map. Always includes global rows (`policyId IS NULL`). When `$policyId`
     * is non-null, also includes that policy's per-policy rows.
     *
     * Words are unique table-wide (single-column unique index) so the
     * map never holds collisions — every word is either global or
     * scoped to exactly one policy.
     *
     * @param int|null $policyId the policy ID to scope the lookup to, or null for global only
     * @return array<string, string> word → source ('common' | 'custom')
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getWordsForPolicy(?int $policyId): array
    {
        return $this->getWordsForPolicies($policyId === null ? [] : [$policyId]);
    }

    /**
     * Returns the merged blocklist for the given policy IDs as a
     * `[word => source]` map. Always includes global rows. Convenience for
     * users resolved to multiple policies — `PolicyResolverService` returns
     * a multi-policy set when per-group policies are enabled and a user
     * belongs to overlapping groups.
     *
     * Reads through the full-table cache once and filters in-memory; the
     * cache shape is `[word => ['source' => ..., 'policyId' => ...]]` so
     * filtering doesn't require a second DB round-trip.
     *
     * @param int[] $policyIds the policy IDs to scope the lookup to (empty = global only)
     * @return array<string, string> word → source ('common' | 'custom')
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getWordsForPolicies(array $policyIds): array
    {
        $full = $this->_getFullBlocklist();
        $allowed = array_flip(array_map('intval', $policyIds));
        $merged = [];

        foreach ($full as $word => $row) {
            // Global rows always pass; per-policy rows pass only when
            // their policyId is in the allowed set.
            if ($row['policyId'] === null || isset($allowed[$row['policyId']])) {
                $merged[$word] = $row['source'];
            }
        }

        return $merged;
    }

    /**
     * Looks up a single word against the blocklist (case-insensitive).
     * Used by the in-CP "check a word" tool so admins / auditors can
     * verify lineage without dumping the whole list.
     *
     * @param string $word
     * @return array{blocked: bool, source: string|null}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isBlocked(#[\SensitiveParameter] string $word): array
    {
        $word = strtolower(trim($word));

        if ($word === '') {
            return ['blocked' => false, 'source' => null];
        }

        $row = (new Query())
            ->select(['source'])
            ->from('{{%passwordpolicy_blocklist}}')
            ->where(['word' => $word])
            ->one();

        if (!$row) {
            return ['blocked' => false, 'source' => null];
        }

        return ['blocked' => true, 'source' => (string)$row['source']];
    }

    /**
     * Returns the count of common passwords in the blocklist.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getCommonCount(): int
    {
        return (int)(new Query())
            ->from('{{%passwordpolicy_blocklist}}')
            ->where(['source' => 'common'])
            ->count();
    }

    /**
     * Checks if a word is in the blocklist.
     *
     * @param string $word
     * @return string|null The source ('common' or 'custom') if found, null if not
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function isWordBlocked(string $word): ?string
    {
        $word = strtolower(trim($word));

        return (new Query())
            ->select(['source'])
            ->from('{{%passwordpolicy_blocklist}}')
            ->where(['word' => $word])
            ->scalar() ?: null;
    }

    /**
     * Returns the date of the most recent common password entry.
     *
     * @return DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getLastUpdated(): ?DateTime
    {
        $date = (new Query())
            ->select(['dateCreated'])
            ->from('{{%passwordpolicy_blocklist}}')
            ->where(['source' => 'common'])
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit(1)
            ->scalar();

        if ($date === false) {
            return null;
        }

        return new DateTime($date);
    }

    /**
     * Invalidates every cached blocklist projection.
     *
     * Both the legacy validator key (`CACHE_KEY`, owned by the cache
     * primer in `CommonPasswordValidator::_getBlocklist()`) and the full-
     * table key (`CACHE_KEY_FULL`, used for the per-policy filter path)
     * are dropped. Mutations call this from `addCustomWord` /
     * `removeCustomWord` / `seedCommonPasswords` so the next read sees
     * the fresh row set.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function clearCache(): void
    {
        $cache = Craft::$app->getCache();
        $cache->delete(self::CACHE_KEY);
        $cache->delete(self::CACHE_KEY_FULL);
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the full blocklist as `[word => ['source' => ..., 'policyId' => ...]]`,
     * cached for an hour. Reused by `getWordsForPolicy()` and
     * `getWordsForPolicies()` so per-policy filters never hit the DB
     * after the first call in a request.
     *
     * @return array<string, array{source: string, policyId: int|null}>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getFullBlocklist(): array
    {
        $cache = Craft::$app->getCache();
        $cached = $cache->get(self::CACHE_KEY_FULL);

        if (is_array($cached)) {
            return $cached;
        }

        $rows = (new Query())
            ->select(['word', 'source', 'policyId'])
            ->from('{{%passwordpolicy_blocklist}}')
            ->all();

        // The unique index on `word` guarantees one row per word; the
        // map can be built in a single pass with no precedence logic.
        $full = [];
        foreach ($rows as $row) {
            $full[(string)$row['word']] = [
                'source' => (string)$row['source'],
                'policyId' => $row['policyId'] !== null ? (int)$row['policyId'] : null,
            ];
        }

        // 1 hour TTL matches the legacy validator cache.
        $cache->set(self::CACHE_KEY_FULL, $full, 3600);

        return $full;
    }
}
