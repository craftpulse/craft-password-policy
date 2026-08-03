<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\migrations;

use Craft;
use craft\db\Migration;
use craft\db\Query;
use craft\db\Table;
use craft\services\ProjectConfig as ProjectConfigService;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class m260729_010858_KebabCasePermissions
 *
 * Renames the settings permission handle to its kebab-case form
 * ({@see PasswordPolicy::PERMISSION_MANAGE_SETTINGS}, `pp:manage-settings`),
 * carrying existing grants over so nobody loses access. Permission handles are
 * kebab-case across the CraftPulse plugin estate; this was the plugin's only
 * handle that was not.
 *
 * Two earlier forms are covered:
 *
 *  - `pp:settings` — the handle 5.1.x released, so real installs hold grants
 *    against it.
 *  - `pp:manageSettings` — the intermediate camelCase form used during 5.2.0
 *    development. Never released, but development and QA installs hold it.
 *
 * Craft lowercases a permission name both when it stores it and when it checks
 * it (see {@see \craft\services\UserPermissions}), so the database and project
 * config hold `pp:settings` / `pp:managesettings` while the new code checks
 * `pp:manage-settings`. A code-only rename would therefore stop matching
 * silently, and it would fail invisibly: an admin holds every permission
 * implicitly and would notice nothing, while every non-admin grantee would lose
 * the settings and policies screens.
 *
 * For each old handle the migration moves the user grants
 * ({@see Table::USERPERMISSIONS_USERS}), the group grants
 * ({@see Table::USERPERMISSIONS_USERGROUPS}), and the project-config group lists
 * (`users.groups.<uid>.permissions`) onto the new name, then drops the old
 * permission row so no dead handle is left behind. Grant sets are UNIONed rather
 * than replaced, so an install that carries both old forms (or a pre-existing row
 * on the new name) keeps every grantee from every row.
 *
 * The project config is written with events muted and the read-only flag
 * temporarily lifted (the same pairing {@see \craft\services\ProjectConfig::rebuild()}
 * uses): the grant rows are rewritten here directly, so the group-permission
 * change handler has nothing left to reconcile, and the rename must land even on
 * an install running with `allowAdminChanges` disabled.
 *
 * The migration is idempotent. Each handle is skipped unless its old permission
 * row actually exists, and a project-config list is only rewritten when it still
 * carries an old name.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260729_010858_KebabCasePermissions extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws \Throwable
     * @throws \yii\base\ErrorException
     * @throws \yii\base\Exception
     * @throws \yii\base\NotSupportedException
     * @throws \yii\db\Exception
     * @throws \yii\web\ServerErrorHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeUp(): bool
    {
        $this->_renamePermissions($this->_upMap());

        return true;
    }

    /**
     * @inheritdoc
     *
     * @throws \Throwable
     * @throws \yii\base\ErrorException
     * @throws \yii\base\Exception
     * @throws \yii\base\NotSupportedException
     * @throws \yii\db\Exception
     * @throws \yii\web\ServerErrorHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeDown(): bool
    {
        $this->_renamePermissions($this->_downMap());

        return true;
    }

    // Private Methods
    // =========================================================================

    /**
     * The forward rename map, lowercased on both sides the way Craft stores
     * permission names. Keyed by an old handle, valued with the kebab-case
     * handle the plugin code now owns.
     *
     * @return array<string, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _upMap(): array
    {
        return $this->_lowercase([
            'pp:settings' => PasswordPolicy::PERMISSION_MANAGE_SETTINGS,
            'pp:manageSettings' => PasswordPolicy::PERMISSION_MANAGE_SETTINGS,
        ]);
    }

    /**
     * The reverse rename map. Two old handles collapse onto one new handle, so
     * the reverse is not a mechanical flip of {@see self::_upMap()} — rolling
     * this migration back returns the install to the code state immediately
     * before it, which is the 5.2.0 development line's `pp:manageSettings`.
     *
     * @return array<string, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _downMap(): array
    {
        return $this->_lowercase([
            PasswordPolicy::PERMISSION_MANAGE_SETTINGS => 'pp:manageSettings',
        ]);
    }

    /**
     * Lowercases both sides of a rename map, matching how Craft normalises
     * permission names on write and on check.
     *
     * @param array<string, string> $map
     * @return array<string, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _lowercase(array $map): array
    {
        $lowercased = [];

        foreach ($map as $old => $new) {
            $lowercased[strtolower($old)] = strtolower($new);
        }

        return $lowercased;
    }

    /**
     * Moves every grant of each old permission name onto its new name, in the
     * grant tables and in the project-config group lists, then removes the old
     * permission rows.
     *
     * @param array<string, string> $map Old permission name to new permission name, both lowercased.
     * @return void
     *
     * @throws \Throwable
     * @throws \yii\base\ErrorException
     * @throws \yii\base\Exception
     * @throws \yii\base\NotSupportedException
     * @throws \yii\db\Exception
     * @throws \yii\web\ServerErrorHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renamePermissions(array $map): void
    {
        foreach ($map as $oldPermission => $newPermission) {
            $this->_renameGrants($oldPermission, $newPermission);
        }

        $this->_rewriteProjectConfig($map);
    }

    /**
     * Repoints one permission's user and group grants at the new name and drops
     * the old permission row. A no-op when the old permission is not present, so
     * the migration can run twice.
     *
     * Grants are UNIONed across the old row and any pre-existing row on the new
     * name before both rows are replaced by a single new-name row. Dropping the
     * new row's grants instead would be silent data loss on an install that
     * already holds the new handle — reachable here because two old handles map
     * onto the same new one.
     *
     * @param string $oldPermission
     * @param string $newPermission
     * @return void
     *
     * @throws \yii\db\Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renameGrants(string $oldPermission, string $newPermission): void
    {
        $oldPermissionId = (new Query())
            ->select(['id'])
            ->from([Table::USERPERMISSIONS])
            ->where(['name' => $oldPermission])
            ->scalar($this->db);

        if ($oldPermissionId === false || $oldPermissionId === null) {
            return;
        }

        $newPermissionId = (new Query())
            ->select(['id'])
            ->from([Table::USERPERMISSIONS])
            ->where(['name' => $newPermission])
            ->scalar($this->db);

        $permissionIds = [$oldPermissionId];

        if ($newPermissionId !== false && $newPermissionId !== null) {
            $permissionIds[] = $newPermissionId;
        }

        $userIds = $this->_grantees(Table::USERPERMISSIONS_USERS, 'userId', $permissionIds);
        $groupIds = $this->_grantees(Table::USERPERMISSIONS_USERGROUPS, 'groupId', $permissionIds);

        // Drop the old row (cascading its grants away) plus any row that already
        // carries the new name, so the insert below cannot collide with a
        // half-applied run. Both grant sets were read above.
        $this->delete(Table::USERPERMISSIONS, ['id' => $permissionIds]);

        $this->insert(Table::USERPERMISSIONS, ['name' => $newPermission]);
        $insertedId = $this->db->getLastInsertID(Table::USERPERMISSIONS);

        if ($userIds !== []) {
            $this->batchInsert(
                Table::USERPERMISSIONS_USERS,
                ['permissionId', 'userId'],
                array_map(static fn(int|string $userId): array => [$insertedId, $userId], $userIds),
            );
        }

        if ($groupIds !== []) {
            $this->batchInsert(
                Table::USERPERMISSIONS_USERGROUPS,
                ['permissionId', 'groupId'],
                array_map(static fn(int|string $groupId): array => [$insertedId, $groupId], $groupIds),
            );
        }
    }

    /**
     * Reads the distinct grantee ids held against any of the given permission
     * ids — the union of the old row's grants and the new row's, so no grantee
     * is dropped when both rows exist.
     *
     * @param string $table The grant join table.
     * @param string $column The grantee column (`userId` or `groupId`).
     * @param array<int, int|string> $permissionIds
     * @return array<int, int|string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _grantees(string $table, string $column, array $permissionIds): array
    {
        return array_values(array_unique((new Query())
            ->select([$column])
            ->from([$table])
            ->where(['permissionId' => $permissionIds])
            ->column($this->db)));
    }

    /**
     * Swaps the old permission names for the new ones in every user group's
     * project-config permission list, keeping Craft's stored shape (lowercased,
     * sorted ascending, sequentially keyed).
     *
     * @param array<string, string> $map Old permission name to new permission name, both lowercased.
     * @return void
     *
     * @throws \Throwable
     * @throws \yii\base\ErrorException
     * @throws \yii\base\Exception
     * @throws \yii\base\NotSupportedException
     * @throws \yii\web\ServerErrorHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _rewriteProjectConfig(array $map): void
    {
        $projectConfig = Craft::$app->getProjectConfig();
        $groups = $projectConfig->get(ProjectConfigService::PATH_USER_GROUPS) ?? [];

        if (!is_array($groups)) {
            return;
        }

        $muteEvents = $projectConfig->muteEvents;
        $readOnly = $projectConfig->readOnly;
        $projectConfig->muteEvents = true;
        $projectConfig->readOnly = false;

        try {
            foreach ($groups as $uid => $group) {
                if (!is_array($group)) {
                    continue;
                }

                $permissions = $group['permissions'] ?? [];

                if (!is_array($permissions) || $permissions === []) {
                    continue;
                }

                $renamed = array_map(
                    static fn(mixed $permission): mixed => is_string($permission)
                        ? ($map[strtolower($permission)] ?? $permission)
                        : $permission,
                    $permissions,
                );

                if ($renamed === $permissions) {
                    continue;
                }

                $renamed = array_values(array_unique($renamed));
                sort($renamed);

                $projectConfig->set(
                    sprintf('%s.%s.permissions', ProjectConfigService::PATH_USER_GROUPS, $uid),
                    $renamed,
                    'Rename Password Policy permission handles to kebab-case',
                );
            }
        } finally {
            $projectConfig->muteEvents = $muteEvents;
            $projectConfig->readOnly = $readOnly;
        }
    }
}
