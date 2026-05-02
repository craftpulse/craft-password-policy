<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support\Factories;

use Carbon\Carbon;
use Craft;
use craft\elements\User;
use craft\helpers\StringHelper;
use yii\db\Exception;

/**
 * Test factory for `passwordpolicy_password_history` rows.
 *
 * Bcrypt seed loops are a well-known leak — Yii's debug logger captures
 * every bound parameter, which would put plaintext-derived hashes (and
 * potentially the plaintexts themselves under verbose logging) into the
 * test framework's debug output. The factory toggles `enableLogging` and
 * `enableProfiling` off around the insert loop and restores them in
 * `finally`, mirroring `m260429_*UpgradeTo520Schema::_seedPasswordHistory()`
 * — the production seed path with the same security guarantee.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordHistoryFactory
{
    // Public Methods
    // =========================================================================

    /**
     * Seeds password history rows for a user with each plaintext bcrypt-
     * hashed and ordered oldest-first. Pass `$keepCount` to trim the seeded
     * set (older entries dropped) — matches the production prune semantics.
     *
     * Hashes are produced via `Craft::$app->getSecurity()->hashPassword()`
     * so they match the production format exactly. Each row also gets a
     * fresh `uid` and a `dateCreated` that increments per slot — without
     * distinct timestamps the validator's `ORDER BY dateCreated DESC`
     * fetch would non-deterministically pick which N entries it sees.
     *
     * @param User $user
     * @param string[] $plaintexts ordered oldest-first
     * @param int|null $keepCount  trims to last N entries; null = keep all
     * @return void
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function seedFor(User $user, array $plaintexts, ?int $keepCount = null): void
    {
        if (empty($plaintexts)) {
            return;
        }

        if ($keepCount !== null && $keepCount > 0 && count($plaintexts) > $keepCount) {
            $plaintexts = array_slice($plaintexts, -$keepCount);
        }

        $db = Craft::$app->getDb();
        $security = Craft::$app->getSecurity();

        $wasLogging = $db->enableLogging;
        $wasProfiling = $db->enableProfiling;

        $db->enableLogging = false;
        $db->enableProfiling = false;

        try {
            $now = Carbon::now('UTC');

            foreach (array_values($plaintexts) as $offset => $plaintext) {
                // Each row gets a distinct timestamp so the ORDER BY
                // dateCreated query has a deterministic ordering even
                // when the loop runs faster than 1s.
                $stamp = $now->copy()->subSeconds(count($plaintexts) - $offset)
                    ->format('Y-m-d H:i:s');

                $db->createCommand()
                    ->insert('{{%passwordpolicy_password_history}}', [
                        'userId' => $user->id,
                        'passwordHash' => $security->hashPassword($plaintext),
                        'dateCreated' => $stamp,
                        'uid' => StringHelper::UUID(),
                    ])
                    ->execute();
            }
        } finally {
            $db->enableLogging = $wasLogging;
            $db->enableProfiling = $wasProfiling;
        }
    }
}
