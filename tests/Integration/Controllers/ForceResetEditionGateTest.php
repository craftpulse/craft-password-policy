<?php
/**
 * Pest coverage for the Pro gate, and the peer-admin guard, on PER-USER force
 * password reset.
 *
 * Force reset splits along the mass/per-user line, not along an edition line
 * drawn through one capability:
 *
 *  - The MASS path (Password Retention utility, `retention/force-reset-passwords`
 *    console command) is universal on every edition. It reaches only accounts a
 *    retention sweep already found expired, it shipped in 5.1.2 before the
 *    plugin had editions, and `pp:force-reset-passwords` gates it on Lite too
 *    (asserted in `Integration/Permissions/EditionGatedPermissionsTest`).
 *  - The PER-USER path is the additive Pro capability: a named account, expired
 *    or not. Three surfaces drive it (the `ForcePasswordReset` bulk element
 *    action, the user-edit action-menu item, and the Actions pane on the
 *    Password Security screen), all of them behind `pp:user-force-reset`, which
 *    registers on Pro+ only.
 *
 * Which leaves three things to hold together, and this file pins the third:
 *
 *  1. `pp:user-force-reset` registers on Pro+ only (asserted in
 *     `Integration/Permissions/EditionGatedPermissionsTest`).
 *  2. The Password Security pane is absent below Pro (asserted in
 *     `Integration/UserEditTab/PasswordSecurityTabTest`).
 *  3. `UserSecurityController::actionForceReset()` gates on edition BEFORE
 *     permission, and refuses a non-admin aiming at an admin regardless of
 *     permission — in both directions and against every axis.
 *
 * Edition before permission matters: a 403 would confirm the endpoint exists,
 * which is exactly the signal the hidden pane withholds. And because admins
 * clear every `can()` check but no edition check, the Lite case is asserted
 * with an ADMIN identity too — if the order were reversed, an admin on Lite
 * would sail through the permission gate and reach the action body.
 *
 * The peer-admin guard is the opposite axis and answers 403, not 404: on Pro the
 * endpoint exists and the caller does hold the grant, so the denial is about who
 * the TARGET is. `pp:user-force-reset` is grantable to non-admins by design, and
 * flagging an administrator's account is an escalation primitive, so the
 * permission must not carry it.
 *
 * Grants are fixtured through `PermissionFactory`, which writes raw inserts
 * rather than going through `UserPermissions::saveUserPermissions()` — see that
 * class for why the service path can't express the cases under test here.
 *
 * @link      https://craft-pulse.com
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
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\PermissionFactory;
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
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([PasswordPolicy::PERMISSION_USER_FORCE_RESET]));

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

it('forces the reset on Pro for a non-admin holding pp:user-force-reset', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([PasswordPolicy::PERMISSION_USER_FORCE_RESET]));

    $target = UserFactory::nonAdmin();

    runForceResetPastFlash((int)$target->id);

    expect(passwordResetRequiredFor((int)$target->id))->toBeTrue();
});

it('pins AdminForceReset rather than ExpiryForced on the per-user path', function() {
    // The per-user path is an operator pointing at one account, not a retention
    // sweep reaching it, so the pending reason the next password change records
    // has to say so. The mass path keeps `ExpiryForced`.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::nonAdmin();

    runForceResetPastFlash((int)$target->id);

    $state = UserStateRecord::findOne(['userId' => $target->id]);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
});

// =============================================================================
// Pro — 403 without the permission
// =============================================================================

it('403s the force-reset POST on Pro without pp:user-force-reset', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    // `pp:change-user-passwords` clears the controller-wide `beforeAction()`
    // predicate (either admin-on-user permission grants tab visibility), so
    // the 403 comes from the action's own `requirePermission()` and not from
    // the screen gate. On Pro the endpoint DOES exist, so 403 is the honest
    // answer — the 404 is reserved for the edition that doesn't have it.
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith(['pp:change-user-passwords']));

    $target = UserFactory::nonAdmin();

    expect(fn() => runForceReset((int)$target->id))->toThrow(ForbiddenHttpException::class);

    expect(passwordResetRequiredFor((int)$target->id))->toBeFalse();
});

it('403s the force-reset POST on Pro when the mass grant is the only one held', function() {
    // The two handles are not interchangeable. Holding the universal mass grant
    // buys the retention utility's expired-only sweep and nothing else; it must
    // not open the per-user endpoint.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([
        PasswordPolicy::PERMISSION_FORCE_RESET_PASSWORDS,
        'pp:change-user-passwords',
    ]));

    $target = UserFactory::nonAdmin();

    expect(fn() => runForceReset((int)$target->id))->toThrow(ForbiddenHttpException::class);

    expect(passwordResetRequiredFor((int)$target->id))->toBeFalse();
});

// =============================================================================
// Peer-admin guard — a non-admin may not aim this at an admin
// =============================================================================

it('403s the force-reset POST when a non-admin targets an admin', function() {
    // The escalation this closes: `pp:user-force-reset` is grantable to
    // non-admins, and without the guard a holder could flag every
    // administrator's account, forcing a credential change on accounts they
    // have no authority over. Permission held, edition satisfied, target
    // resolved — and still refused, because the denial is about WHO the target
    // is.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([PasswordPolicy::PERMISSION_USER_FORCE_RESET]));

    $target = UserFactory::admin();

    expect(fn() => runForceReset((int)$target->id))->toThrow(ForbiddenHttpException::class);

    // No write, and no pending reason pinned either — the guard fires before
    // the service is reached, so nothing partial lands.
    expect(passwordResetRequiredFor((int)$target->id))->toBeFalse()
        ->and(UserStateRecord::findOne(['userId' => $target->id]))->toBeNull();
});

it('lets an admin force-reset another admin', function() {
    // The guard is about peers crossing a privilege boundary, not about admin
    // accounts being untouchable. Co-administrators are peers, and Craft
    // already treats them as mutually trusted, so an admin actor passes.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->userStub->setIdentity(UserFactory::admin());

    $target = UserFactory::admin();

    runForceResetPastFlash((int)$target->id);

    expect(passwordResetRequiredFor((int)$target->id))->toBeTrue();
});
