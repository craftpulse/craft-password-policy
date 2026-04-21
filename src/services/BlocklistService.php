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
use DateTime;
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
     * @var string
     */
    private const CACHE_KEY = 'passwordpolicy_blocklist_words';

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
     * @param string $word
     * @return bool Whether the word was added (false if duplicate)
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function addCustomWord(string $word): bool
    {
        $word = strtolower(trim($word));

        if (empty($word)) {
            return false;
        }

        // Check for duplicates
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
     * Invalidates the cached blocklist word set.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function clearCache(): void
    {
        Craft::$app->getCache()->delete(self::CACHE_KEY);
    }
}
