<?php
/**
 * Pest coverage for the front-end `PasswordChangeController` — the POST
 * target behind the `passwordChangeForm()` Twig builder. Pins the C-phase
 * review fix that replaced `User::authenticate()` with a side-effect-free
 * hash compare for the current-password check.
 *
 * `authenticate()` was wrong for this surface on two counts:
 *
 *  1. It returns FALSE for a CORRECT password when `passwordResetRequired`
 *     is set (its post-validate `_getAuthError()` pass rejects reset-required
 *     users) — locking out exactly the expired / reset-required users this
 *     change form exists to serve.
 *  2. It fires `EVENT_BEFORE_AUTHENTICATE` (HIBP-on-login + breach
 *     notification / audit against the discarded OLD password) and
 *     `handleInvalidLogin()` (lockout penalties) as side effects of what is
 *     a password CHANGE, not a login.
 *
 * The fix uses `Craft::$app->getSecurity()->validatePassword()` directly.
 * These tests lock in: a reset-required user with the CORRECT current
 * password is accepted (password actually changes), and the
 * `EVENT_BEFORE_AUTHENTICATE` listener never fires during the change.
 *
 * The controller is exercised through `runAction()` so `beforeAction()`
 * (POST requirement) fires in the same order it would on a real request —
 * mirroring `UserPasswordControllerTest` and `DestroyOtherSessionsTest`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\front\PasswordChangeController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\base\Event;
use yii\web\ForbiddenHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalEdition = $this->plugin->edition;
    $this->originalMinLength = $this->settings->minLength;
    $this->originalHistoryCount = $this->settings->passwordHistoryCount;
    $this->originalIsSystemLive = Craft::$app->getConfig()->getGeneral()->isSystemLive;

    // Front-end web context: site request, POST.
    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = false;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Mark the system as live so Craft's Controller::_enforceAllowAnonymous()
    // follows the live-system path. Without this, the console-bootstrapped test
    // application reports the system offline (project config `system.live` is
    // not set to `true` in the test DB), and any non-admin site request without
    // `accessSiteWhenSystemIsOff` triggers a ServiceUnavailableHttpException
    // before the controller's own ForbiddenHttpException gates fire.
    Craft::$app->getConfig()->getGeneral()->isSystemLive = true;

    // Permissive policy + no history so the new password saves cleanly.
    $this->settings->minLength = 6;
    $this->settings->passwordHistoryCount = 0;
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    $this->settings->minLength = $this->originalMinLength;
    $this->settings->passwordHistoryCount = $this->originalHistoryCount;
    Craft::$app->getConfig()->getGeneral()->isSystemLive = $this->originalIsSystemLive;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs `PasswordChangeController::actionSave()` through `runAction()` so the
 * controller's `beforeAction()` POST gate fires in the right order.
 */
function runPasswordChangeSave(): mixed
{
    $controller = new PasswordChangeController('password-change', PasswordPolicy::$plugin);

    return $controller->runAction('save');
}

// =============================================================================
// Current-password check — reset-required acceptance + no side effects
// =============================================================================

it('accepts a reset-required user with the correct current password', function() {
    $currentPassword = 'Current-Pass-1!';

    // Build a user with a known current password and the reset-required
    // flag set — the very state that `User::authenticate()` would have
    // rejected despite a correct password.
    $user = UserFactory::nonAdmin([
        'newPassword' => $currentPassword,
        'passwordResetRequired' => true,
    ]);

    expect($user->password)->not->toBeEmpty();

    $this->userStub->setIdentity($user);

    $this->request->stubBodyParams = [
        'currentPassword' => $currentPassword,
        'newPassword' => 'Brand-New-Pass-2!',
        'newPasswordConfirm' => 'Brand-New-Pass-2!',
    ];

    $response = runPasswordChangeSave();

    // A redirect Response (not a 400/model-failure) means the save went
    // through — the reset-required user was NOT locked out.
    expect($response)->toBeInstanceOf(Response::class)
        ->and($user->hasErrors())->toBeFalse();

    // The password actually changed: the old hash no longer validates, the
    // new one does.
    // `UserQuery::beforePrepare()` does NOT select `users.password` — re-fetching
    // via `User::find()` would yield a null `password` property. Read the hash
    // directly from the `users` table, matching the plugin's own idiom for
    // columns that the element query intentionally omits.
    $freshHash = (new Query())
        ->select(['password'])
        ->from(Table::USERS)
        ->where(['id' => $user->id])
        ->scalar();
    expect($freshHash)->not->toBeNull();
    expect(Craft::$app->getSecurity()->validatePassword($currentPassword, (string)$freshHash))
        ->toBeFalse();
    expect(Craft::$app->getSecurity()->validatePassword('Brand-New-Pass-2!', (string)$freshHash))
        ->toBeTrue();
});

it('does not fire EVENT_BEFORE_AUTHENTICATE during a password change', function() {
    $currentPassword = 'Current-Pass-1!';

    $user = UserFactory::nonAdmin([
        'newPassword' => $currentPassword,
        'passwordResetRequired' => true,
    ]);

    $this->userStub->setIdentity($user);

    // Attach a sentinel listener — the change flow must use a side-effect-free
    // hash compare, so this must never fire (it would mean HIBP-on-login /
    // breach-notification / lockout side effects ran against the OLD password).
    $fired = false;
    $handler = function() use (&$fired): void {
        $fired = true;
    };
    Event::on(User::class, User::EVENT_BEFORE_AUTHENTICATE, $handler);

    try {
        $this->request->stubBodyParams = [
            'currentPassword' => $currentPassword,
            'newPassword' => 'Brand-New-Pass-2!',
            'newPasswordConfirm' => 'Brand-New-Pass-2!',
        ];

        runPasswordChangeSave();
    } finally {
        Event::off(User::class, User::EVENT_BEFORE_AUTHENTICATE, $handler);
    }

    expect($fired)->toBeFalse();
});

it('rejects a wrong current password without changing the stored hash', function() {
    $currentPassword = 'Current-Pass-1!';

    $user = UserFactory::nonAdmin([
        'newPassword' => $currentPassword,
    ]);

    $this->userStub->setIdentity($user);

    $this->request->stubBodyParams = [
        'currentPassword' => 'totally-wrong',
        'newPassword' => 'Brand-New-Pass-2!',
        'newPasswordConfirm' => 'Brand-New-Pass-2!',
    ];

    $response = runPasswordChangeSave();

    // Model-failure response carries a 400; the user picks up a
    // `currentPassword` error and the stored hash is untouched.
    expect($response)->toBeInstanceOf(Response::class)
        ->and($user->getErrors('currentPassword'))->not->toBeEmpty();

    // Same pattern as the happy-path test — `UserQuery` omits `users.password`.
    $freshHash = (new Query())
        ->select(['password'])
        ->from(Table::USERS)
        ->where(['id' => $user->id])
        ->scalar();
    expect(Craft::$app->getSecurity()->validatePassword($currentPassword, (string)$freshHash))
        ->toBeTrue();
});

it('rejects a confirm mismatch with a newPasswordConfirm error', function() {
    $currentPassword = 'Current-Pass-1!';

    $user = UserFactory::nonAdmin([
        'newPassword' => $currentPassword,
    ]);

    $this->userStub->setIdentity($user);

    $this->request->stubBodyParams = [
        'currentPassword' => $currentPassword,
        'newPassword' => 'Brand-New-Pass-2!',
        'newPasswordConfirm' => 'different-value',
    ];

    $response = runPasswordChangeSave();

    expect($response)->toBeInstanceOf(Response::class)
        ->and($user->getErrors('newPasswordConfirm'))->not->toBeEmpty();
});

// =============================================================================
// Auth gate
// =============================================================================

it('throws ForbiddenHttpException when no user is logged in', function() {
    $this->userStub->setIdentity(null);

    $this->request->stubBodyParams = [
        'currentPassword' => 'x',
        'newPassword' => 'y',
        'newPasswordConfirm' => 'y',
    ];

    runPasswordChangeSave();
})->throws(ForbiddenHttpException::class);
