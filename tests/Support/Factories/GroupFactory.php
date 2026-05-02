<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support\Factories;

use Craft;
use craft\enums\CmsEdition;
use craft\models\UserGroup;
use Throwable;
use yii\base\Exception;

/**
 * Test factory for `craft\models\UserGroup` instances.
 *
 * Per-group password policies require user groups, and Craft only allows
 * `UserGroups::saveGroup()` to run on the Pro edition or higher. The factory
 * elevates `Craft::$app->edition` defensively before each call so a
 * Solo-default test app can still seed groups for resolver coverage. The
 * elevation is process-local and doesn't touch project config — when the
 * test process exits, nothing leaks.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GroupFactory
{
    // Public Methods
    // =========================================================================

    /**
     * Creates and saves a `UserGroup` with sensible defaults. Pass
     * `$overrides` to set specific properties (handle, name) before save.
     *
     * Each call generates a unique handle/name suffix so multiple groups
     * coexist within a single test process.
     *
     * @param array<string, mixed> $overrides
     * @return UserGroup
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function create(array $overrides = []): UserGroup
    {
        self::ensureCmsProEdition();

        $unique = bin2hex(random_bytes(4));

        $group = new UserGroup([
            'name' => "Test Group {$unique}",
            'handle' => "testGroup{$unique}",
        ]);

        foreach ($overrides as $property => $value) {
            $group->{$property} = $value;
        }

        if (!Craft::$app->getUserGroups()->saveGroup($group)) {
            throw new Exception(sprintf(
                'GroupFactory::create failed to save group: %s',
                implode('; ', $group->getFirstErrors()),
            ));
        }

        return $group;
    }

    /**
     * Convenience helper — creates a group with the conventional "editors"
     * handle/name. Equivalent to calling `create()` with the matching
     * overrides; lets resolver tests read `editors()` instead of inline
     * config noise.
     *
     * @return UserGroup
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function editors(): UserGroup
    {
        $unique = bin2hex(random_bytes(4));

        return self::create([
            'name' => "Editors {$unique}",
            'handle' => "editors{$unique}",
        ]);
    }

    /**
     * Convenience helper — creates a group with the conventional "managers"
     * handle/name. Same rationale as `editors()`.
     *
     * @return UserGroup
     *
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function managers(): UserGroup
    {
        $unique = bin2hex(random_bytes(4));

        return self::create([
            'name' => "Managers {$unique}",
            'handle' => "managers{$unique}",
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Ensures Craft is running on at least the Pro edition before any
     * `UserGroups::saveGroup()` call. Solo (the install default) refuses to
     * persist user groups via `requireEdition(CmsEdition::Pro)`.
     *
     * Mutating `$app->edition` directly is the right move for tests — it's
     * a public typed property, sticks for the duration of the process, and
     * doesn't touch project config (which would break the per-test
     * transaction wrapper).
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function ensureCmsProEdition(): void
    {
        if (Craft::$app->edition->value < CmsEdition::Pro->value) {
            Craft::$app->edition = CmsEdition::Pro;
        }
    }
}
