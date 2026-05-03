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

    /**
     * Stubbed return value for `getHasElevatedSession()`. Used by D3
     * controller tests to flip the elevated-session gate without
     * standing up real session storage. Defaults to `true` (elevated)
     * so tests opt into "no elevation" by setting `false` explicitly.
     *
     * @var bool
     *
     * @since 5.2.0
     */
    public bool $stubHasElevatedSession = true;

    /**
     * Mirror of `yii\web\User::$idParam` — Craft internals
     * (`Sites::getCurrentSite()`, `App::env()` resolution paths) read
     * `Craft::$app->getUser()->idParam` directly even when the user
     * is the console flavour. Console `User` doesn't define this
     * property, so the read falls through to `Component::__get` and
     * throws `UnknownPropertyException`. The stub mirrors the web
     * default so those reads return a safe value.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public string $idParam = '__id';

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

    /**
     * Stubbed elevated-session check used by `Controller::requireElevatedSession()`.
     * The console `User` doesn't define this method natively; the
     * D3 controller tests run in a web-shaped request stub and call
     * the web `Controller::requireElevatedSession()`, which delegates
     * here. Returning `false` lets tests assert on the
     * `UserException` thrown by the requirement.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getHasElevatedSession(): bool
    {
        return $this->stubHasElevatedSession;
    }
}
