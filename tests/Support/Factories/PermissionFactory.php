<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support\Factories;

use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craft\errors\ElementNotFoundException;
use Throwable;
use yii\base\Exception;
use yii\db\Exception as DbException;

/**
 * Test factory for user permission grants.
 *
 * Grants are written with raw inserts rather than
 * `craft\services\UserPermissions::saveUserPermissions()`, for two reasons:
 *
 *  1. That method runs the incoming list through `_filterOrphanedPermissions()`,
 *     which drops any handle the current edition doesn't register. It therefore
 *     cannot express "a grant made on Pro that survived a downgrade to Lite",
 *     which is precisely the case the edition-gate tests need.
 *  2. It reads `getAllPermissions()`, which memoizes into a private property with
 *     no reset. The first call in the process fixes the permission tree at
 *     whatever edition happened to be live then, making any test that switches
 *     editions order-dependent.
 *
 * Lives in `Support` rather than as a Pest helper function because Pest hoists
 * test-file functions into one global namespace, so every file that needed this
 * had to invent its own name for the same code.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PermissionFactory
{
    // Public Methods
    // =========================================================================

    /**
     * Grants the given permissions to a user, reusing an existing
     * `userpermissions` row when the handle is already known (matching
     * `UserPermissions`' own upsert-by-name behaviour).
     *
     * Handles are lowercased on the way in, exactly as Craft does on write and
     * on check.
     *
     * @param int $userId
     * @param string[] $permissions
     * @return void
     *
     * @throws DbException if a grant row fails to insert.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function grant(int $userId, array $permissions): void
    {
        $db = Craft::$app->getDb();

        foreach ($permissions as $permission) {
            $name = strtolower($permission);

            $permissionId = (new Query())
                ->select(['id'])
                ->from(Table::USERPERMISSIONS)
                ->where(['name' => $name])
                ->scalar();

            if ($permissionId === false || $permissionId === null) {
                $db->createCommand()->insert(Table::USERPERMISSIONS, ['name' => $name])->execute();
                $permissionId = $db->getLastInsertID(Table::USERPERMISSIONS);
            }

            $db->createCommand()
                ->insert(Table::USERPERMISSIONS_USERS, [
                    'permissionId' => (int)$permissionId,
                    'userId' => $userId,
                ])
                ->execute();
        }
    }

    /**
     * Creates a non-admin holding CP access plus the given permissions, and
     * returns the re-fetched user so `can()` reflects the grants.
     *
     * Re-fetching matters: `User::can()` reads a permission set loaded when the
     * element was hydrated, so the instance the factory saved would report
     * `false` for every grant written afterwards.
     *
     * @param string[] $permissions
     * @return User
     *
     * @throws DbException if a grant row fails to insert.
     * @throws ElementNotFoundException
     * @throws Exception
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function nonAdminWith(array $permissions): User
    {
        $user = UserFactory::nonAdmin();

        self::grant(
            (int)$user->id,
            array_merge(['accessCp', 'accessCpWhenSystemIsOff'], $permissions),
        );

        return Craft::$app->getUsers()->getUserById((int)$user->id);
    }
}
