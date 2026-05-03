<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support\Factories;

use Craft;
use craft\elements\User;
use craft\enums\CmsEdition;
use craft\errors\ElementNotFoundException;
use Throwable;
use yii\base\Exception;

/**
 * Test factory for `craft\elements\User` instances.
 *
 * Factories own the boilerplate of building a valid Craft user — unique
 * email, sensible defaults, save through the Elements service so element
 * lifecycle events fire — and let tests focus on the behaviour under
 * exam. Pass `$overrides` to vary the bits a specific test cares about
 * (password, group membership, lastPasswordChangeDate, etc.).
 *
 * Add factory methods here only when the helper genuinely abstracts a
 * pattern — single-test fixtures stay inline. `PolicyFactory`,
 * `GroupFactory`, and `BlocklistFactory` will land alongside the E2/E3
 * tests that need them.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserFactory
{
    // Public Methods
    // =========================================================================

    /**
     * Creates and saves an admin user with sensible defaults. Pass
     * `$overrides` to set specific properties before save.
     *
     * The email + username are uniquely suffixed so multiple admins can
     * coexist within a single test process — each call is a fresh user.
     *
     * @param array<string, mixed> $overrides
     * @return User
     *
     * @throws ElementNotFoundException
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function admin(array $overrides = []): User
    {
        // Solo edition caps install at one user — and the bootstrap already
        // created the seed admin. Elevate to Pro before saving so additional
        // test users can persist. Mutating `$app->edition` directly is the
        // right move here: it sticks for the test process and doesn't write
        // project config (which would break the per-test transaction wrap).
        if (Craft::$app->edition->value < CmsEdition::Pro->value) {
            Craft::$app->edition = CmsEdition::Pro;
        }

        $unique = bin2hex(random_bytes(4));

        $user = new User([
            'admin' => true,
            'username' => "admin-{$unique}",
            'email' => "admin-{$unique}@craftpulse.test",
            'firstName' => 'Test',
            'lastName' => 'Admin',
        ]);

        foreach ($overrides as $property => $value) {
            $user->{$property} = $value;
        }

        if (!Craft::$app->getElements()->saveElement($user)) {
            throw new Exception(
                sprintf(
                    'UserFactory::admin failed to save user: %s',
                    implode('; ', $user->getFirstErrors()),
                ),
            );
        }

        return $user;
    }

    /**
     * Creates and saves a non-admin user. Non-admin users do NOT
     * automatically pass every `User::can()` check the way admins do
     * (Solo edition is a separate fallthrough — non-admins on Solo
     * still pass every check). Use for permission-denial tests where
     * an admin's auto-grant would mask the gate.
     *
     * @param array<string, mixed> $overrides
     * @return User
     *
     * @throws ElementNotFoundException
     * @throws Throwable
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function nonAdmin(array $overrides = []): User
    {
        if (Craft::$app->edition->value < CmsEdition::Pro->value) {
            Craft::$app->edition = CmsEdition::Pro;
        }

        $unique = bin2hex(random_bytes(4));

        $user = new User([
            'admin' => false,
            'username' => "user-{$unique}",
            'email' => "user-{$unique}@craftpulse.test",
            'firstName' => 'Test',
            'lastName' => 'User',
        ]);

        foreach ($overrides as $property => $value) {
            $user->{$property} = $value;
        }

        if (!Craft::$app->getElements()->saveElement($user)) {
            throw new Exception(
                sprintf(
                    'UserFactory::nonAdmin failed to save user: %s',
                    implode('; ', $user->getFirstErrors()),
                ),
            );
        }

        return $user;
    }
}
