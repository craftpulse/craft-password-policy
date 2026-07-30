<?php
/**
 * Pest coverage for the Pro gate on force password reset.
 *
 * Force reset has three CP surfaces: the `ForcePasswordReset` bulk element
 * action on the Users index, the "Force password reset" item in the user-edit
 * action menu, and the Actions pane on the user-edit Password Security screen.
 * The first two were Pro from the start; the pane was not, so a Lite operator
 * could still force a reset from it. All three are Pro now, which means three
 * things have to hold together:
 *
 *  1. `pp:force-reset-passwords` registers on Pro+ only (asserted in
 *     `Integration/Permissions/EditionGatedPermissionsTest`).
 *  2. The Password Security pane is absent below Pro (asserted in
 *     `Integration/UserEditTab/PasswordSecurityTabTest`).
 *  3. `UserSecurityController::actionForceReset()` gates on edition BEFORE
 *     permission, so a Lite POST answers 404 and not 403 — which is what this
 *     file pins, in both directions and against both axes.
 *
 * Edition before permission matters: a 403 would confirm the endpoint exists,
 * which is exactly the signal the hidden pane withholds. And because admins
 * clear every `can()` check but no edition check, the Lite case is asserted
 * with an ADMIN identity too — if the order were reversed, an admin on Lite
 * would sail through the permission gate and reach the action body.
 *
 * Grants are fixtured with raw inserts rather than
 * `UserPermissions::saveUserPermissions()`. That method runs the incoming list
 * through `_filterOrphanedPermissions()`, which drops any handle the current
 * edition doesn't register — so it can't express "a grant made on Pro that
 * survived a downgrade to Lite", which is precisely the case under test. It
 * would also be order-dependent: `getAllPermissions()` memoizes into a private
 * property with no reset, so the first call in the process fixes the tree at
 * whatever edition happened to be live then.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craft\errors\MissingComponentException;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\UserSecurityController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalRetentionUtilities = $this->settings->retentionUtilities;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalResponse = Craft::$app->getResponse();

    // The action short-circuits to a failure response when retention features
    // are off, which would mask the gate under test in both directions.
    $this->settings->retentionUtilities = true;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    $this->request->stubIsPost = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->retentionUtilities = $this->originalRetentionUtilities;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->set('response', $this->originalResponse);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs `UserSecurityController::actionForceReset()` through `runAction()` so
 * `beforeAction()` and the action's own gates fire in the real order.
 */
function runForceReset(int $targetUserId): mixed
{
    Craft::$app->getRequest()->setBodyParams(['userId' => $targetUserId]);

    $controller = new UserSecurityController('user-security', PasswordPolicy::$plugin);

    return $controller->runAction('force-reset');
}

/**
 * Runs the force-reset action and swallows only the console-session failure.
 *
 * On success the action calls `setSuccessFlash()`, which reaches
 * `Craft::$app->getSession()` — and `craft\console\Application::getSession()`
 * throws by design. The flash isn't what's under test; reaching it at all means
 * every gate was cleared and the write already happened, so each caller then
 * asserts the write itself. A 404 or 403 propagates.
 */
function runForceResetPastFlash(int $targetUserId): void
{
    try {
        runForceReset($targetUserId);
    } catch (MissingComponentException) {
        // `craft\console\Application::getSession()` throws by design; nothing
        // else in the action path raises this.
    }
}

/**
 * Grants permissions to a user with raw inserts, bypassing
 * `UserPermissions::saveUserPermissions()`'s orphan filter (see the file
 * docblock for why). Reuses an existing `userpermissions` row when the handle
 * is already known, matching the service's own upsert-by-name behaviour.
 *
 * @param string[] $permissions
 */
function ppRawGrantPermissions(int $userId, array $permissions): void
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
 * Creates a non-admin holding CP access plus whatever extra permissions are
 * passed, and returns the re-fetched user so `can()` reflects the grants.
 *
 * Named distinctly from `SettingsPermissionGateTest`'s equivalent: Pest hoists
 * these into the global function namespace, so two files can't both declare
 * `nonAdminWithPermissions()`.
 *
 * @param string[] $extraPermissions
 */
function forceResetCaller(array $extraPermissions = []): \craft\elements\User
{
    $user = UserFactory::nonAdmin();

    ppRawGrantPermissions(
        (int)$user->id,
        array_merge(['accessCp', 'accessCpWhenSystemIsOff'], $extraPermissions),
    );

    return Craft::$app->getUsers()->getUserById((int)$user->id);
}

/**
 * Reads `passwordResetRequired` straight out of the users table.
 * `craft\elements\db\UserQuery` doesn't select the column, so a re-fetched
 * element would always report `false`.
 */
function passwordResetRequiredFor(int $userId): bool
{
    return (bool)(new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $userId])
        ->scalar();
}

// =============================================================================
// Lite — the POST 404s, even for an admin
// =============================================================================

it('404s the force-reset POST on Lite for an admin', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();

    // Admin identity clears every permission check, so a 404 here can only
    // come from the edition gate — and its position before the permission gate
    // is what keeps an admin out.
    expect(fn() => runForceReset((int)$target->id))->toThrow(NotFoundHttpException::class);

    expect(passwordResetRequiredFor((int)$target->id))->toBeFalse();
});

it('404s the force-reset POST on Lite for a non-admin holding the grant', function() {
    // A grant made on Pro survives a downgrade untouched (Craft never prunes
    // `userpermissions` rows for unregistered names), so on Lite the edition
    // gate is the only thing between the holder and this endpoint. It has to
    // answer 404, not 403.
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->userStub->setIdentity(forceResetCaller(['pp:force-reset-passwords']));

    $target = UserFactory::nonAdmin();

    expect(fn() => runForceReset((int)$target->id))->toThrow(NotFoundHttpException::class);

    expect(passwordResetRequiredFor((int)$target->id))->toBeFalse();
});

// =============================================================================
// Pro — works with the permission
// =============================================================================

it('forces the reset on Pro for an admin', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();

    runForceResetPastFlash((int)$target->id);

    expect(passwordResetRequiredFor((int)$target->id))->toBeTrue();
});

it('forces the reset on Pro for a non-admin holding pp:force-reset-passwords', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(forceResetCaller(['pp:force-reset-passwords']));

    $target = UserFactory::nonAdmin();

    runForceResetPastFlash((int)$target->id);

    expect(passwordResetRequiredFor((int)$target->id))->toBeTrue();
});

// =============================================================================
// Pro — 403 without the permission
// =============================================================================

it('403s the force-reset POST on Pro without pp:force-reset-passwords', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    // `pp:change-user-passwords` clears the controller-wide `beforeAction()`
    // predicate (either admin-on-user permission grants tab visibility), so
    // the 403 comes from the action's own `requirePermission()` and not from
    // the screen gate. On Pro the endpoint DOES exist, so 403 is the honest
    // answer — the 404 is reserved for the edition that doesn't have it.
    $this->userStub->setIdentity(forceResetCaller(['pp:change-user-passwords']));

    $target = UserFactory::nonAdmin();

    expect(fn() => runForceReset((int)$target->id))->toThrow(ForbiddenHttpException::class);

    expect(passwordResetRequiredFor((int)$target->id))->toBeFalse();
});
