<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craft\console\User as ConsoleUser;

/**
 * Lightweight stub that extends `craft\console\User` to add a stubbable
 * `getToken()` for tests exercising the web-context branch of
 * `PasswordService::destroyOtherSessions()`.
 *
 * The bootstrap boots Craft as a `craft\console\Application`, and
 * `ConsoleApplication::getUser()` is type-hinted to return
 * `craft\console\User`. The stub satisfies that covariance while adding
 * the `getToken()` method the helper expects to call when
 * `getIsConsoleRequest()` returns false (which a `WebRequestStub`
 * supplies).
 *
 * Tests set `$stubToken` to the token they want the helper to treat as
 * "current"; setting it to `null` exercises the no-token branch where
 * every session for the user (including the would-be current one) gets
 * destroyed.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserStub extends ConsoleUser
{
    // Public Properties
    // =========================================================================

    /**
     * The token value `getToken()` returns. `null` simulates a
     * mid-authentication state where no session token exists yet.
     *
     * @var string|null
     *
     * @since 5.2.0
     */
    public ?string $stubToken = null;

    // Public Methods
    // =========================================================================

    /**
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getToken(): ?string
    {
        return $this->stubToken;
    }
}
