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
use craft\db\Query;
use craft\db\Table;
use yii\db\Exception;

/**
 * Test factory for `craft_sessions` rows.
 *
 * `PasswordService::destroyOtherSessions()` operates against the sessions
 * table directly — the factory matches that contract by inserting via
 * `Craft::$app->getDb()`. Each call returns the inserted token so callers
 * can assert specific rows survived (or didn't) after the helper runs.
 *
 * Tokens are random hex blobs to satisfy the `craft_sessions.token` UNIQUE
 * constraint across the test process.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SessionFactory
{
    // Public Methods
    // =========================================================================

    /**
     * Inserts a single `craft_sessions` row for the supplied user. Returns
     * the generated token so the caller can build query conditions or
     * pass it as the "current" token to `destroyOtherSessions()`.
     *
     * @param int $userId
     * @return string the generated session token
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function create(int $userId): string
    {
        $token = bin2hex(random_bytes(16));

        Craft::$app->getDb()->createCommand()
            ->insert(Table::SESSIONS, [
                'userId' => $userId,
                'token' => $token,
                'dateCreated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
            ])
            ->execute();

        return $token;
    }

    /**
     * Returns the count of session rows currently held for the given user.
     * Tests use this to assert the helper deleted the expected number of
     * rows.
     *
     * @param int $userId
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function countFor(int $userId): int
    {
        return (int)(new Query())
            ->from(Table::SESSIONS)
            ->where(['userId' => $userId])
            ->count('*', Craft::$app->getDb());
    }

    /**
     * Returns whether a row with the supplied token exists in the sessions
     * table. Used to assert that the "current" token survived the delete.
     *
     * @param string $token
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function tokenExists(string $token): bool
    {
        return (new Query())
            ->from(Table::SESSIONS)
            ->where(['token' => $token])
            ->exists(Craft::$app->getDb());
    }
}
