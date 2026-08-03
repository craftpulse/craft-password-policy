<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support\Factories;

use Carbon\Carbon;
use Craft;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\db\Exception;

/**
 * Test factory for `passwordpolicy_blocklist` rows.
 *
 * The validator's cache layer is shared global state — every helper here
 * also flushes the cache via `BlocklistService::clearCache()` so the next
 * read of `CommonPasswordValidator::_getBlocklist()` rebuilds against the
 * fresh row set. Tests that seed words and then validate without the flush
 * see stale cached data.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BlocklistFactory
{
    // Public Methods
    // =========================================================================

    /**
     * Inserts a row with `source = 'common'`. Mirrors what the bundled
     * SecLists seed produces — bundled common entries always have a NULL
     * `policyId` and trip the validator with the "too common" message.
     *
     * @param string $word
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function commonWord(string $word): void
    {
        self::insert($word, 'common', null);
    }

    /**
     * Inserts a row with `source = 'custom'` and the supplied `policyId`
     * (or NULL for global custom entries). The policyId scoping field
     * shipped in P1.11 — currently every Pro-tier custom write passes
     * NULL, but the schema column exists so resolver tests can verify
     * future per-policy behavior doesn't regress.
     *
     * @param string $word
     * @param int|null $policyId
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function customWord(string $word, ?int $policyId = null): void
    {
        self::insert($word, 'custom', $policyId);
    }

    // Private Methods
    // =========================================================================

    /**
     * Shared INSERT path. Source-aware error messages depend on the row's
     * `source` value being either `'common'` or `'custom'` — those are
     * the only two values the validator branches on.
     *
     * @param string $word
     * @param string $source
     * @param int|null $policyId
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function insert(string $word, string $source, ?int $policyId): void
    {
        Craft::$app->getDb()->createCommand()
            ->insert('{{%passwordpolicy_blocklist}}', [
                'word' => strtolower(trim($word)),
                'source' => $source,
                'policyId' => $policyId,
                'dateCreated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
            ])
            ->execute();

        PasswordPolicy::$plugin->getBlocklist()->clearCache();
    }
}
