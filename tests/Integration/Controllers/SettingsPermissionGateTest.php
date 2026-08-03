<?php
/**
 * Pest coverage for the estate settings-permission doctrine on
 * {@see SettingsController}: the settings screens are gated by the
 * {@see PasswordPolicy::PERMISSION_MANAGE_SETTINGS} permission in
 * `beforeAction()`, never by `requireAdmin`.
 *
 * Pins:
 *
 *  - A non-admin WITHOUT the permission gets a 403 (the permission gate fires
 *    before any action body runs).
 *  - A non-admin WITH the permission clears the gate and reaches the action
 *    body (the permission gate does NOT throw — a later template-render error
 *    in the console-bootstrapped process is out of scope).
 *  - An admin always clears the gate (admins hold every permission).
 *
 * `craft\console\User::checkPermission()` delegates to the identity's `can()`,
 * so a real non-admin element assigned the permission exercises the gate
 * exactly as an HTTP request would. `UserFactory::nonAdmin()` forces the Craft
 * edition to Pro so permission checks engage (Solo passes everyone).
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\controllers\SettingsController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->originalEdition = Craft::$app->edition;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalResponse = Craft::$app->getResponse();

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new \craft\web\Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);
});

afterEach(function() {
    Craft::$app->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->set('response', $this->originalResponse);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs `SettingsController::actionEdit('configuration')` through `runAction()`
 * so the `requirePermission()` gate in `beforeAction()` fires.
 */
function runSettingsGate(): mixed
{
    $controller = new SettingsController('settings', PasswordPolicy::$plugin);

    return $controller->runAction('edit', ['section' => 'configuration']);
}

/**
 * Creates a non-admin granted the base CP-access permissions plus whatever
 * extra permissions are passed, and returns the re-fetched user so `can()`
 * reflects the grant. `accessCp` + `accessCpWhenSystemIsOff` clear Craft's own
 * control-panel access chain, so the `pp:manage-settings` gate under test is the
 * only discriminator between the two non-admin cases.
 *
 * @param string[] $extraPermissions
 */
function nonAdminWithPermissions(array $extraPermissions = []): \craft\elements\User
{
    $user = UserFactory::nonAdmin();

    Craft::$app->getUserPermissions()->saveUserPermissions(
        (int)$user->id,
        array_merge(['accessCp', 'accessCpWhenSystemIsOff'], $extraPermissions),
    );

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

// =============================================================================
// Non-admin WITHOUT the permission → 403
// =============================================================================

it('403s a non-admin without the manage-settings permission', function() {
    // Holds CP access but NOT manage-settings — the permission gate must fire.
    $this->userStub->setIdentity(nonAdminWithPermissions());

    expect(fn() => runSettingsGate())->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// Non-admin WITH the permission → clears the gate
// =============================================================================

it('lets a non-admin with the manage-settings permission through the gate', function() {
    $this->userStub->setIdentity(nonAdminWithPermissions([PasswordPolicy::PERMISSION_MANAGE_SETTINGS]));

    // The permission gate must NOT throw. The action body renders a settings
    // template that fails in the console-bootstrapped process; any non-403
    // throwable means the gate was cleared, which is the assertion under test.
    $forbidden = false;

    try {
        runSettingsGate();
    } catch (ForbiddenHttpException) {
        $forbidden = true;
    } catch (\Throwable) {
        // Passed the permission gate; a later render error is out of scope.
    }

    expect($forbidden)->toBeFalse('Non-admin holding pp:manage-settings was wrongly denied the settings screen');
});

// =============================================================================
// Admin → always clears the gate
// =============================================================================

it('lets an admin through the gate', function() {
    $this->userStub->setIdentity(UserFactory::admin());

    $forbidden = false;

    try {
        runSettingsGate();
    } catch (ForbiddenHttpException) {
        $forbidden = true;
    } catch (\Throwable) {
        // Passed the permission gate; a later render error is out of scope.
    }

    expect($forbidden)->toBeFalse('Admin was wrongly denied the settings screen');
});
