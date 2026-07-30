<?php
/**
 * Pest coverage for `UserPasswordController` — the CP POST target for
 * D3's `ChangeUserPassword` and `SendPasswordResetEmail` element
 * actions. Pins:
 *
 *  - `actionChange()` writes a history row with `changeReason =
 *    admin_change` + `changedByUserId = currentAdminId`. Pending
 *    reason gets cleared. Self-target rejected. Confirm mismatch
 *    rejected. Bulk-shaped POST rejected.
 *  - `actionSendResetEmail()` pins the `AdminForceReset` pending
 *    reason and invokes Craft's mailer.
 *  - Permission gate (no `pp:change-user-passwords` → 403).
 *  - Elevated session gate (stub returns false → 403).
 *  - Read-only mode (`allowAdminChanges = false` → 403 on both
 *    actions).
 *
 * The tests exercise the controller through reflection on the
 * `actionChange` / `actionSendResetEmail` methods rather than a full
 * HTTP round-trip — `Controller::beforeAction()` is called directly
 * via `runAction` so the gates fire in the right order. This matches
 * the pattern used in `ValidationControllerTest` and
 * `DestroyOtherSessionsTest`.
 *
 * The plugin's history listener writes synchronously inside
 * `EVENT_AFTER_SAVE`; the test reads `passwordpolicy_password_history`
 * after `actionChange` and asserts on the persisted row's audit columns
 * directly.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\UserPasswordController;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\MailerFixture;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    // Stash bootstrap components so afterEach can restore them.
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalEdition = $this->plugin->edition;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;
    $this->originalHistoryCount = $this->settings->passwordHistoryCount;
    $this->originalMinLength = $this->settings->minLength;
    $this->originalCases = $this->settings->cases;
    $this->originalNumbers = $this->settings->numbers;
    $this->originalSymbols = $this->settings->symbols;
    $this->originalForceChange = $this->settings->forceChangeOnFirstLogin;

    // Default web/CP context: CP request, JSON-accepting, elevated
    // session true, admin identity authenticated.
    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Pro edition needed so password history actually writes (the
    // central listener gates the history row on `getIsPro()`).
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->passwordHistoryCount = 5;

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    // Acting admin — the user that the controller checks
    // `Craft::$app->getUser()->getIdentity()` for.
    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);
});

afterEach(function() {
    MailerFixture::restore();

    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    $this->settings->passwordHistoryCount = $this->originalHistoryCount;
    $this->settings->minLength = $this->originalMinLength;
    $this->settings->cases = $this->originalCases;
    $this->settings->numbers = $this->originalNumbers;
    $this->settings->symbols = $this->originalSymbols;
    $this->settings->forceChangeOnFirstLogin = $this->originalForceChange;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs the controller action through `Controller::runAction()` so
 * `beforeAction()` fires (CP request + POST + permission + elevated
 * session) in the same order it would in a real HTTP request.
 */
function runUserPasswordAction(string $actionId): mixed
{
    $controller = new UserPasswordController('user-password', PasswordPolicy::$plugin);

    return $controller->runAction($actionId);
}

// =============================================================================
// actionChange — happy path
// =============================================================================

it('writes a history row with admin_change + changedByUserId on success', function() {
    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    $response = runUserPasswordAction('change');

    expect($response)->toBeInstanceOf(Response::class);

    $row = (new Query())
        ->select(['changeReason', 'changedByUserId'])
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $target->id])
        ->orderBy(['dateCreated' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull()
        ->and($row['changeReason'])->toBe(ChangeReason::AdminChange->value)
        ->and((int)$row['changedByUserId'])->toBe($this->actingAdmin->id);
});

it('clears any prior pending reason on success', function() {
    $target = UserFactory::nonAdmin();

    // Pre-pin a stale pending reason — admin direct intent should
    // override on the next save.
    $this->plugin->getUserState()->setPendingReason($target, ChangeReason::BreachForced);

    expect(UserStateRecord::findOne(['userId' => $target->id])?->pendingResetReason)
        ->toBe(ChangeReason::BreachForced->value);

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    runUserPasswordAction('change');

    // Pending reason cleared; the history row records the explicit
    // admin context instead of the stale pending reason.
    $state = UserStateRecord::findOne(['userId' => $target->id]);
    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBeNull();

    $row = (new Query())
        ->select(['changeReason'])
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $target->id])
        ->orderBy(['dateCreated' => SORT_DESC])
        ->one();

    expect($row['changeReason'])->toBe(ChangeReason::AdminChange->value);
});

it('rejects when the new password fails policy validation', function() {
    // Pin a strict global policy: 12-char minimum + complexity + cases
    // requirement. The new password "weak" is too short and missing
    // required types — the User element's defineRules listener picks
    // up `UserRules::defineRules()` which runs the per-group resolver
    // and rejects on save.
    $this->settings->minLength = 12;
    $this->settings->cases = true;
    $this->settings->numbers = true;
    $this->settings->symbols = true;

    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'weak',
        'newPasswordConfirm' => 'weak',
    ];

    $response = runUserPasswordAction('change');

    expect($response)->toBeInstanceOf(Response::class)
        ->and($response->getStatusCode())->toBe(400);

    // No history row written — the save failed.
    $count = (new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $target->id])
        ->count();
    expect((int)$count)->toBe(0);

    // The explicit-context slot pinned before save should have been
    // drained by the controller's failure path (otherwise a follow-up
    // unrelated save would pick up a stale `AdminChange` context).
    $consumed = $this->plugin->getUserState()->consumeExplicitContext($target);
    expect($consumed)->toBeNull();
});

// =============================================================================
// actionChange — force-change-on-first-login preservation
// =============================================================================
//
// Craft's `User::afterSave` clears `passwordResetRequired` whenever
// `newPassword` is set on a non-new user that previously had the flag
// (`vendor/craftcms/cms/src/elements/User.php` line 2632). That clear
// is correct for ordinary admin password changes — admin reset on
// behalf of an established user — and unwanted for initial-password-
// setup flows where admin assigned a *temporary* password to a brand-
// new user under the `forceChangeOnFirstLogin` policy. The controller
// re-asserts the flag after save for the second case only.
//
// These tests pin both halves of the split: preservation for the
// initial-setup case (force-change on + user never logged in + flag
// was true pre-save) and Craft's default clear for everything else.
//
// 2026-05-22 Phase H smoke test S1.6 motivated this.

it('preserves passwordResetRequired when admin sets initial password under force-change policy', function() {
    $this->settings->forceChangeOnFirstLogin = true;

    // Fresh user. With `forceChangeOnFirstLogin = true` set above, the
    // plugin's own EVENT_AFTER_SAVE listener (registered at boot) fires
    // synchronously inside the factory's saveElement, sets
    // `passwordResetRequired = true`, and re-saves. So by the time
    // `UserFactory::nonAdmin()` returns, the DB row for the user has
    // `passwordResetRequired = true` — exactly the "fresh + flag set +
    // never logged in" state the controller's preservation gate looks
    // for. Note: `User::find()` and `getUserById()` will still report
    // `$user->passwordResetRequired = false` because Craft's UserQuery
    // doesn't select that column; the controller reads from the DB
    // directly, same pattern the plugin uses for `lastPasswordChangeDate`.
    $target = UserFactory::nonAdmin();

    $dbFlag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$dbFlag)->toBeTrue();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    runUserPasswordAction('change');

    // Direct DB read — `UserQuery::beforePrepare()` doesn't select
    // `passwordResetRequired`, so re-fetching via `getUserById()` or
    // `User::find()` would surface `false` regardless of DB state.
    $postFlag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$postFlag)->toBeTrue();
});

it('lets Craft clear passwordResetRequired when admin changes password for an established user', function() {
    // Policy is enabled, but irrelevant — the established-user gate
    // below trips the preservation. Test the "user has logged in
    // before" path.
    $this->settings->forceChangeOnFirstLogin = true;

    $target = UserFactory::nonAdmin();
    $target->passwordResetRequired = true;
    expect(Craft::$app->getElements()->saveElement($target, false))->toBeTrue();

    // Stamp `lastLoginDate` directly on the users row so the controller's
    // `lastLoginDate === null` gate evaluates false. User::afterSave
    // doesn't touch this column on save, so the DB-direct write survives
    // the controller's subsequent `saveElement` call.
    Craft::$app->getDb()->createCommand()
        ->update('{{%users}}', [
            'lastLoginDate' => \craft\helpers\Db::prepareDateForDb(new DateTime('-1 day')),
        ], ['id' => $target->id])
        ->execute();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    runUserPasswordAction('change');

    // Craft's standard semantic survives — admin set a new password on
    // a user who's already engaged with the system, so the flag clears.
    // Direct DB read for the same reason as the previous test.
    $postFlag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$postFlag)->toBeFalse();
});

it('does not re-assert passwordResetRequired when force-change policy is off', function() {
    $this->settings->forceChangeOnFirstLogin = false;

    $target = UserFactory::nonAdmin();
    $target->passwordResetRequired = true;
    expect(Craft::$app->getElements()->saveElement($target, false))->toBeTrue();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    runUserPasswordAction('change');

    // Policy off + flag had been set incidentally (manual admin flip
    // earlier, etc.). No policy reason to sustain it through the save —
    // Craft's clear holds.
    $postFlag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$postFlag)->toBeFalse();
});

it('re-pins FirstLoginForced so the preserved forced reset is captured accurately', function() {
    $this->settings->forceChangeOnFirstLogin = true;

    // Fresh user under the force-change policy: the plugin's creation
    // listener set `passwordResetRequired = true` + pinned a
    // `FirstLoginForced` pending reason.
    $target = UserFactory::nonAdmin();
    expect(UserStateRecord::findOne(['userId' => $target->id])?->pendingResetReason)
        ->toBe(ChangeReason::FirstLoginForced->value);

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    runUserPasswordAction('change');

    // The admin-change save consumed the pending reason and wrote an
    // AdminChange history row (the admin's action). Because the flag was
    // preserved, the user still owes a forced first-login reset — so the
    // controller re-pins FirstLoginForced. Without the re-pin, that
    // eventual reset would mis-record as self_service.
    $state = UserStateRecord::findOne(['userId' => $target->id]);
    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::FirstLoginForced->value);

    // The admin's own change still recorded admin_change.
    $row = (new Query())
        ->select(['changeReason'])
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $target->id])
        ->orderBy(['dateCreated' => SORT_DESC])
        ->one();
    expect($row['changeReason'])->toBe(ChangeReason::AdminChange->value);
});

// =============================================================================
// actionChange — defensive gates
// =============================================================================

it('rejects bulk-shaped POSTs (userId as array)', function() {
    $a = UserFactory::nonAdmin();
    $b = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => [$a->id, $b->id],
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    expect(fn() => runUserPasswordAction('change'))
        ->toThrow(\yii\web\BadRequestHttpException::class);
});

it('rejects self-targeted password change', function() {
    $this->request->stubBodyParams = [
        'userId' => $this->actingAdmin->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    expect(fn() => runUserPasswordAction('change'))
        ->toThrow(\yii\web\BadRequestHttpException::class);
});

it('rejects when newPassword and confirm do not match', function() {
    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'Different!',
    ];

    $response = runUserPasswordAction('change');

    // asModelFailure returns the response; for JSON-accepting requests
    // it's a 400 with the errors map.
    expect($response)->toBeInstanceOf(Response::class)
        ->and($response->getStatusCode())->toBe(400);

    // No history row written because the save never happened.
    $count = (new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $target->id])
        ->count();
    expect((int)$count)->toBe(0);
});

it('returns 404 when target user does not exist', function() {
    $this->request->stubBodyParams = [
        'userId' => 999999,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    expect(fn() => runUserPasswordAction('change'))
        ->toThrow(\yii\web\NotFoundHttpException::class);
});

// =============================================================================
// actionChange — permission gate
// =============================================================================

it('rejects callers without pp:change-user-passwords (non-admin without permission)', function() {
    $nonAdmin = UserFactory::nonAdmin();
    $this->userStub->setIdentity($nonAdmin);

    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    expect(fn() => runUserPasswordAction('change'))
        ->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// actionChange — elevated session gate
// =============================================================================

it('rejects when the session is not elevated', function() {
    $this->userStub->stubHasElevatedSession = false;

    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    expect(fn() => runUserPasswordAction('change'))
        ->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// actionChange — read-only mode
// =============================================================================

it('rejects when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
        'newPassword' => 'NewStr0ngP@ssword!',
        'newPasswordConfirm' => 'NewStr0ngP@ssword!',
    ];

    expect(fn() => runUserPasswordAction('change'))
        ->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// actionSendResetEmail — pending reason + mailer
// =============================================================================

it('pins AdminForceReset pending reason on send', function() {
    $target = UserFactory::nonAdmin();

    // Buffer outgoing mail and pin a valid sender so
    // `sendPasswordResetEmail()` returns true without an SMTP transport.
    // The fixture snapshots the previous state; `afterEach` restores it, so
    // this test can no longer hand a working mailer to whatever runs next.
    MailerFixture::pin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
    ];

    $response = runUserPasswordAction('send-reset-email');

    expect($response)->toBeInstanceOf(Response::class);

    $state = UserStateRecord::findOne(['userId' => $target->id]);
    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
});

it('rejects send-reset-email when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
    ];

    expect(fn() => runUserPasswordAction('send-reset-email'))
        ->toThrow(ForbiddenHttpException::class);
});

it('rejects send-reset-email when the session is not elevated', function() {
    $this->userStub->stubHasElevatedSession = false;

    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
    ];

    expect(fn() => runUserPasswordAction('send-reset-email'))
        ->toThrow(ForbiddenHttpException::class);
});

it('rejects send-reset-email without pp:change-user-passwords', function() {
    $nonAdmin = UserFactory::nonAdmin();
    $this->userStub->setIdentity($nonAdmin);

    $target = UserFactory::nonAdmin();

    $this->request->stubBodyParams = [
        'userId' => $target->id,
    ];

    expect(fn() => runUserPasswordAction('send-reset-email'))
        ->toThrow(ForbiddenHttpException::class);
});
