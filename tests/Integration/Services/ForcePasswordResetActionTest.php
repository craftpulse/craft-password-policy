<?php
/**
 * Pest coverage for the `ForcePasswordReset` element action — the bulk
 * "Force Password Reset" button that ships on the Users index. Phase
 * D1.3 wired the action to `UserStateService::setPendingReason()` so
 * the flagged user's NEXT password change records the right
 * `changeReason` in history.
 *
 * The action runs synchronously over a queried element list; tests
 * stand up users via the factory, build a stub query, invoke the
 * action's `performAction()`, and assert on both the User column flip
 * AND the pending-reason write.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\elements\actions\ForcePasswordReset;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\PermissionFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->action = new ForcePasswordReset();

    $this->originalEdition = $this->plugin->edition;
    $this->originalUser = Craft::$app->getUser();
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    // The action only registers on Pro, and `performAction()` re-checks the
    // edition as defense-in-depth against a caller that bypasses the trigger,
    // so the whole file runs on Pro. Per-user force reset is the additive Pro
    // capability; the universal mass path is a different code path entirely
    // (`RetentionService::requirePasswordReset()`).
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    // `performAction()` gates on a logged-in user with the
    // `pp:user-force-reset` permission. An admin identity passes the `can()`
    // check and the peer-admin guard, so the happy-path tests reach the action
    // body even when the targets are admins themselves.
    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);
    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
});

// =============================================================================
// Pending-reason wiring — single user
// =============================================================================

it('flips passwordResetRequired and pins AdminForceReset for a single user', function() {
    $user = UserFactory::admin();

    $query = User::find()->id($user->id);

    expect($this->action->performAction($query))->toBeTrue();

    // Column flip via direct DB query — User element cache may pre-date
    // the action's save, so we read the source of truth column.
    $flag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $user->id])
        ->scalar();
    expect((bool)$flag)->toBeTrue();

    // Pending reason was pinned for the next change.
    $state = UserStateRecord::findOne(['userId' => $user->id]);
    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
});

// =============================================================================
// Already-flagged users — short-circuit to success without re-pinning
// =============================================================================

it('skips users already flagged passwordResetRequired without writing state', function() {
    $user = UserFactory::admin([
        'passwordResetRequired' => true,
    ]);

    // Verify the column actually persisted — Craft's User::beforeSave
    // can reset audit-flag-shaped columns on new admins under some
    // configurations. If it didn't persist, the action's short-circuit
    // branch never fires and this test would assert the wrong thing.
    $persistedFlag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $user->id])
        ->scalar();
    expect((bool)$persistedFlag)->toBeTrue();

    // status(null) so the query doesn't filter pending-/locked-status
    // users — `passwordResetRequired = true` doesn't itself flip status,
    // but pin the broadest fetch so the test asserts only the action's
    // own short-circuit, not the query's filtering.
    $query = User::find()->id($user->id)->status(null);

    expect($this->action->performAction($query))->toBeTrue()
        // No new pending reason — the action's short-circuit branch
        // intentionally avoids re-stamping a state row that may already
        // be tracking a different reason (e.g. ExpiryForced from cron).
        ->and(UserStateRecord::findOne(['userId' => $user->id]))->toBeNull();
});

// =============================================================================
// Permission + admin-changes gate — defense-in-depth in performAction
// =============================================================================

it('refuses to force-reset on Lite even for an admin', function() {
    // Defense-in-depth. The action never registers below Pro, so Craft's
    // `ElementIndexesController` can't resolve it there — but `performAction()`
    // is reachable by any caller that bypasses the trigger, and an admin
    // identity clears every `can()` check, so the edition is the only thing left
    // to reject on.
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $target = UserFactory::nonAdmin();
    $query = User::find()->id($target->id);

    expect($this->action->performAction($query))->toBeFalse();

    $flag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$flag)->toBeFalse()
        ->and(UserStateRecord::findOne(['userId' => $target->id]))->toBeNull();
});

it('refuses to force-reset when the acting user lacks the permission', function() {
    // A non-admin identity does NOT auto-pass `can()`. Without the
    // `pp:user-force-reset` permission the action must reject before
    // touching any user.
    $nonAdmin = UserFactory::nonAdmin();
    $this->userStub->setIdentity($nonAdmin);

    $target = UserFactory::admin();
    $query = User::find()->id($target->id);

    expect($this->action->performAction($query))->toBeFalse();

    // No column flip, no pending reason — the gate fired first.
    $flag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$flag)->toBeFalse()
        ->and(UserStateRecord::findOne(['userId' => $target->id]))->toBeNull();
});

it('refuses to force-reset when admin changes are disabled', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $target = UserFactory::admin();
    $query = User::find()->id($target->id);

    expect($this->action->performAction($query))->toBeFalse();

    $flag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$flag)->toBeFalse();
});

// =============================================================================
// Peer-admin guard — a permitted non-admin may not sweep an admin in
// =============================================================================

it('refuses the whole run when a permitted non-admin targets an admin', function() {
    // The escalation this closes: `pp:user-force-reset` is grantable to
    // non-admins, and a bulk selection is exactly the shape one would use to
    // sweep every administrator in alongside legitimate targets. Permission held
    // and edition satisfied, so the guard is the only thing that can refuse.
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([
        PasswordPolicy::PERMISSION_USER_FORCE_RESET,
    ]));

    $target = UserFactory::admin();
    $query = User::find()->id($target->id)->status(null);

    expect($this->action->performAction($query))->toBeFalse();

    $flag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$flag)->toBeFalse()
        ->and(UserStateRecord::findOne(['userId' => $target->id]))->toBeNull();
});

it('flags a non-admin target for the same permitted non-admin caller', function() {
    // The control case for the guard test above: same actor, same grant, only
    // the target's admin flag differs. Without this pair the guard test would
    // also pass if the permission plumbing were simply broken.
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([
        PasswordPolicy::PERMISSION_USER_FORCE_RESET,
    ]));

    $target = UserFactory::nonAdmin();
    $query = User::find()->id($target->id)->status(null);

    expect($this->action->performAction($query))->toBeTrue();

    $flag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $target->id])
        ->scalar();
    expect((bool)$flag)->toBeTrue();
});

it('refuses the run rather than partially applying it across a mixed selection', function() {
    // An admin swept in alongside non-admins refuses the whole run: silently
    // skipping the admin and reporting success would leave the operator
    // believing every selected account was flagged.
    $this->userStub->setIdentity(PermissionFactory::nonAdminWith([
        PasswordPolicy::PERMISSION_USER_FORCE_RESET,
    ]));

    $admin = UserFactory::admin();
    $nonAdmin = UserFactory::nonAdmin();
    $query = User::find()->id([$admin->id, $nonAdmin->id])->status(null);

    expect($this->action->performAction($query))->toBeFalse();

    $adminFlag = (new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $admin->id])
        ->scalar();

    expect((bool)$adminFlag)->toBeFalse();
});

// =============================================================================
// Bulk path — multiple users, every newly-flagged one gets the pending reason
// =============================================================================

it('pins the pending reason on every newly-flagged user in a bulk run', function() {
    $a = UserFactory::admin();
    $b = UserFactory::admin();
    $c = UserFactory::admin();

    $query = User::find()->id([$a->id, $b->id, $c->id]);

    expect($this->action->performAction($query))->toBeTrue();

    foreach ([$a, $b, $c] as $u) {
        $state = UserStateRecord::findOne(['userId' => $u->id]);
        expect($state)->not->toBeNull()
            ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
    }
});
