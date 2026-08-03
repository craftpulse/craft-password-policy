<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Covers the kebab-case permission rename migration
 * ({@see m260729_010858_KebabCasePermissions}). Craft lowercases a permission
 * name both when it stores it and when it checks it, so a code-only rename would
 * silently stop matching every existing grant, and it would fail invisibly since
 * admins hold everything implicitly.
 *
 * These tests fixture a pre-rename install (the lowercased old name granted to a
 * user, to a group, and listed in a group's project config), run the migration,
 * and assert the grants land on `pp:manage-settings`, the old rows are gone, both
 * old forms are covered, grants are UNIONed rather than replaced, Craft-owned and
 * third-party handles are untouched, the migration is idempotent, and it reverses
 * cleanly on the way down.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use craft\db\Query;
use craft\db\Table as CraftTable;
use craft\elements\User;
use craft\helpers\StringHelper;
use craft\records\UserGroup as UserGroupRecord;
use craftpulse\passwordpolicy\migrations\m260729_010858_KebabCasePermissions;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Builds the migration under test with console output suppressed.
 *
 * @return m260729_010858_KebabCasePermissions
 */
function ppKebabMigration(): m260729_010858_KebabCasePermissions
{
    $migration = new m260729_010858_KebabCasePermissions();
    $migration->compact = true;

    return $migration;
}

/**
 * Grants a permission by its raw stored name, bypassing the UserPermissions
 * service so a pre-rename (lowercased) name can be fixtured.
 * `saveUserPermissions()` and `saveGroupPermissions()` both run the incoming list
 * through `_filterOrphanedPermissions()`, which drops any handle no plugin
 * registers — exactly what makes them unusable for fixturing an old handle.
 *
 * @param string $name
 * @param int|null $userId
 * @param int|null $groupId
 * @return void
 */
function ppGrantRawPermission(string $name, ?int $userId = null, ?int $groupId = null): void
{
    $db = Craft::$app->getDb();
    $db->createCommand()->insert(CraftTable::USERPERMISSIONS, ['name' => $name])->execute();
    $permissionId = (int)$db->getLastInsertID(CraftTable::USERPERMISSIONS);

    if ($userId !== null) {
        $db->createCommand()
            ->insert(CraftTable::USERPERMISSIONS_USERS, ['permissionId' => $permissionId, 'userId' => $userId])
            ->execute();
    }

    if ($groupId !== null) {
        $db->createCommand()
            ->insert(CraftTable::USERPERMISSIONS_USERGROUPS, ['permissionId' => $permissionId, 'groupId' => $groupId])
            ->execute();
    }
}

/**
 * Returns the permission names granted directly to a user.
 *
 * @param int $userId
 * @return string[]
 */
function ppUserPermissionNames(int $userId): array
{
    return (new Query())
        ->select(['p.name'])
        ->from(['p' => CraftTable::USERPERMISSIONS])
        ->innerJoin(['pu' => CraftTable::USERPERMISSIONS_USERS], '[[pu.permissionId]] = [[p.id]]')
        ->where(['pu.userId' => $userId])
        ->column();
}

/**
 * Returns the permission names granted to a user group.
 *
 * @param int $groupId
 * @return string[]
 */
function ppGroupPermissionNames(int $groupId): array
{
    return (new Query())
        ->select(['p.name'])
        ->from(['p' => CraftTable::USERPERMISSIONS])
        ->innerJoin(['pg' => CraftTable::USERPERMISSIONS_USERGROUPS], '[[pg.permissionId]] = [[p.id]]')
        ->where(['pg.groupId' => $groupId])
        ->column();
}

/**
 * Returns every Password Policy permission name currently stored.
 *
 * @return string[]
 */
function ppStoredPermissionNames(): array
{
    return (new Query())
        ->select(['name'])
        ->from([CraftTable::USERPERMISSIONS])
        ->where(['like', 'name', 'pp:'])
        ->column();
}

/**
 * Creates a bare user for a grant fixture. `UserFactory::nonAdmin()` elevates the
 * Craft edition to Pro first — Solo caps the install at one user, which would
 * otherwise leave the fixture with an unsaved (id-less) element.
 *
 * @return User
 *
 * @throws Throwable
 * @throws \craft\errors\ElementNotFoundException
 * @throws \yii\base\Exception
 */
function ppPermissionUser(): User
{
    return UserFactory::nonAdmin();
}

/**
 * Creates a throwaway user group record. Written straight to the record so the
 * fixture needs no particular Craft edition, and so the group's permission list
 * stays under this test's control (and out of project config).
 *
 * @return UserGroupRecord
 */
function ppPermissionGroup(): UserGroupRecord
{
    $handle = 'ppPerm' . bin2hex(random_bytes(4));

    $group = new UserGroupRecord();
    $group->name = $handle;
    $group->handle = $handle;
    $group->uid = StringHelper::UUID();
    $group->save(false);

    return $group;
}

// =============================================================================
// Released handle (pp:settings) → pp:manage-settings
// =============================================================================

it('moves a 5.1.x user grant from pp:settings to the kebab name', function() {
    $user = ppPermissionUser();
    ppGrantRawPermission('pp:settings', userId: (int)$user->id);

    expect(ppUserPermissionNames((int)$user->id))->toContain('pp:settings');

    ppKebabMigration()->safeUp();

    expect(ppUserPermissionNames((int)$user->id))->toContain(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);
    expect(ppUserPermissionNames((int)$user->id))->not->toContain('pp:settings');
});

it('moves a 5.1.x group grant onto the kebab name and drops the old row', function() {
    $group = ppPermissionGroup();
    ppGrantRawPermission('pp:settings', groupId: (int)$group->id);

    ppKebabMigration()->safeUp();

    expect(ppGroupPermissionNames((int)$group->id))->toContain(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);
    expect(ppGroupPermissionNames((int)$group->id))->not->toContain('pp:settings');
    expect(ppStoredPermissionNames())->not->toContain('pp:settings');
});

// =============================================================================
// Development handle (pp:manageSettings) → pp:manage-settings
// =============================================================================

it('moves a 5.2.0 development grant from pp:managesettings to the kebab name', function() {
    $user = ppPermissionUser();
    ppGrantRawPermission('pp:managesettings', userId: (int)$user->id);

    ppKebabMigration()->safeUp();

    expect(ppUserPermissionNames((int)$user->id))->toContain(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);
    expect(ppUserPermissionNames((int)$user->id))->not->toContain('pp:managesettings');
    expect(ppStoredPermissionNames())->not->toContain('pp:managesettings');
});

// =============================================================================
// Both old forms present → grants are unioned, never dropped
// =============================================================================

it('unions the grants when both old handles are present', function() {
    $releasedGrantee = ppPermissionUser();
    $developmentGrantee = ppPermissionUser();
    $releasedGroup = ppPermissionGroup();
    $developmentGroup = ppPermissionGroup();

    ppGrantRawPermission('pp:settings', userId: (int)$releasedGrantee->id, groupId: (int)$releasedGroup->id);
    ppGrantRawPermission('pp:managesettings', userId: (int)$developmentGrantee->id, groupId: (int)$developmentGroup->id);

    ppKebabMigration()->safeUp();

    expect(ppUserPermissionNames((int)$releasedGrantee->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS])
        ->and(ppUserPermissionNames((int)$developmentGrantee->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS])
        ->and(ppGroupPermissionNames((int)$releasedGroup->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS])
        ->and(ppGroupPermissionNames((int)$developmentGroup->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS]);
});

it('keeps a pre-existing grant on the kebab name', function() {
    $oldGrantee = ppPermissionUser();
    $newGrantee = ppPermissionUser();

    ppGrantRawPermission(PasswordPolicy::PERMISSION_MANAGE_SETTINGS, userId: (int)$newGrantee->id);
    ppGrantRawPermission('pp:settings', userId: (int)$oldGrantee->id);

    ppKebabMigration()->safeUp();

    expect(ppUserPermissionNames((int)$newGrantee->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS])
        ->and(ppUserPermissionNames((int)$oldGrantee->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS]);
});

// =============================================================================
// Project config
// =============================================================================

it('rewrites a group project-config permission list, leaving its other handles alone', function() {
    $projectConfig = Craft::$app->getProjectConfig();
    $path = sprintf('users.groups.%s.permissions', StringHelper::UUID());
    $projectConfig->set($path, ['accesscp', 'pp:settings']);

    try {
        ppKebabMigration()->safeUp();

        expect($projectConfig->get($path))
            ->toContain(PasswordPolicy::PERMISSION_MANAGE_SETTINGS)
            ->toContain('accesscp');
        expect($projectConfig->get($path))->not->toContain('pp:settings');
    } finally {
        $projectConfig->remove($path);
    }
});

// =============================================================================
// Idempotency and no-op safety
// =============================================================================

it('is idempotent: running twice does not duplicate or drop grants', function() {
    $user = ppPermissionUser();
    $group = ppPermissionGroup();
    ppGrantRawPermission('pp:settings', userId: (int)$user->id, groupId: (int)$group->id);

    $migration = ppKebabMigration();
    $migration->safeUp();
    $migration->safeUp();

    expect(ppUserPermissionNames((int)$user->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS])
        ->and(ppGroupPermissionNames((int)$group->id))->toBe([PasswordPolicy::PERMISSION_MANAGE_SETTINGS]);
});

it('leaves an install with no legacy Password Policy grants untouched', function() {
    $before = ppStoredPermissionNames();
    sort($before);

    ppKebabMigration()->safeUp();

    $after = ppStoredPermissionNames();
    sort($after);

    expect($after)->toBe($before);
});

// =============================================================================
// Reversal
// =============================================================================

it('reverses the rename on the way down', function() {
    $user = ppPermissionUser();
    ppGrantRawPermission('pp:settings', userId: (int)$user->id);

    $migration = ppKebabMigration();
    $migration->safeUp();

    expect(ppUserPermissionNames((int)$user->id))->toContain(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);

    $migration->safeDown();

    expect(ppUserPermissionNames((int)$user->id))->toContain('pp:managesettings');
    expect(ppUserPermissionNames((int)$user->id))->not->toContain(PasswordPolicy::PERMISSION_MANAGE_SETTINGS);
});

// =============================================================================
// Foreign handles
// =============================================================================

it('does not touch permissions owned by Craft or other plugins', function() {
    $user = ppPermissionUser();
    ppGrantRawPermission('accesscp', userId: (int)$user->id);
    ppGrantRawPermission('utility:queue-manager', userId: (int)$user->id);
    ppGrantRawPermission('pp:blocklist-manage', userId: (int)$user->id);

    ppKebabMigration()->safeUp();

    expect(ppUserPermissionNames((int)$user->id))
        ->toContain('accesscp')
        ->toContain('utility:queue-manager')
        ->toContain('pp:blocklist-manage');
});
