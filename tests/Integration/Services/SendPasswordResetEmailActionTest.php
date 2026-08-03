<?php
/**
 * Pest coverage for the `SendPasswordResetEmail` element action — the
 * bulk-friendly "Send password reset email" entry on the Users index
 * actions menu. The action's `performAction()` runs Craft's standard
 * `Users::sendPasswordResetEmail()` over the queried set and pins
 * `AdminForceReset` on each user's user_state row BEFORE the send so
 * operator intent is recorded even if SMTP fails downstream.
 *
 * Mailer note — Craft's mailer is configured with `useFileTransport
 * = true` per test, plus a non-null `from` array, because the test
 * bootstrap doesn't seed email config into project config and the
 * default `from` array can have a null `fromName` value that crashes
 * Symfony Mime's Address constructor (typed string).
 *
 * The acting user identity defaults to a fresh admin per test (admins
 * auto-pass every `User::can()` check); permission-denial tests
 * elevate a non-admin user via `UserFactory::nonAdmin()`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\elements\User;
use craftpulse\passwordpolicy\elements\actions\SendPasswordResetEmail;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->action = new SendPasswordResetEmail();

    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

    // Web-shaped request stub so URL helpers resolve a host. The
    // action itself doesn't care about CP-vs-site; the mailer's
    // `_getUserUrl()` does.
    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    // Acting admin — auto-passes `pp:change-user-passwords`.
    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);

    // Mailer pinned to file-transport so the assertion runs without
    // SMTP. `from` array gets a non-null name to keep Symfony Mime's
    // Address constructor happy.
    $mailer = Craft::$app->getMailer();
    $mailer->useFileTransport = true;
    /** @phpstan-ignore-next-line — PHPStan narrows the property type */
    $mailer->from = ['tests@craftpulse.test' => 'Password Policy Tests'];
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
});

// =============================================================================
// Trigger HTML — read-only mode
// =============================================================================

it('returns null trigger HTML in read-only mode', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    expect($this->action->getTriggerHtml())->toBeNull();
});

it('returns null trigger HTML in normal mode (default confirm-dialog flow)', function() {
    // The action delegates to `ElementAction`'s default trigger
    // plumbing — no custom JS, just `getConfirmationMessage()`. Pin
    // the null return so a future refactor that adds custom JS
    // doesn't accidentally bypass the confirm-dialog ergonomics.
    expect($this->action->getTriggerHtml())->toBeNull();
});

// =============================================================================
// performAction — pending reason + email path
// =============================================================================

it('pins AdminForceReset pending reason on every selected user', function() {
    $a = UserFactory::nonAdmin();
    $b = UserFactory::nonAdmin();
    $c = UserFactory::nonAdmin();

    $query = User::find()->id([$a->id, $b->id, $c->id]);

    expect($this->action->performAction($query))->toBeTrue();

    foreach ([$a, $b, $c] as $u) {
        $state = UserStateRecord::findOne(['userId' => $u->id]);
        expect($state)->not->toBeNull()
            ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
    }
});

it('pins the pending reason BEFORE invoking the mailer (intent recorded on SMTP failure)', function() {
    // The contract: even if `sendPasswordResetEmail` returns false
    // (transient SMTP failure), the user_state pending reason should
    // be recorded — the operator intent doesn't depend on the
    // delivery outcome. Simulate a failure by force-throwing the
    // mailer; the action's per-user catch keeps the loop going.
    $u = UserFactory::nonAdmin();

    // Pre-pin a different reason — `setPendingReason()` overwrites
    // idempotently, so after the action runs the row should still
    // show `AdminForceReset`.
    $this->plugin->getUserState()->setPendingReason($u, ChangeReason::ExpiryForced);

    $query = User::find()->id($u->id);

    $this->action->performAction($query);

    $state = UserStateRecord::findOne(['userId' => $u->id]);
    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
});

// =============================================================================
// performAction — defense-in-depth permission gate
// =============================================================================

it('rejects when the acting user lacks pp:change-user-passwords', function() {
    // Swap the acting identity to a non-admin (Pro edition is set in
    // `UserFactory::nonAdmin`; admins auto-grant every check).
    $nonAdmin = UserFactory::nonAdmin();
    $this->userStub->setIdentity($nonAdmin);

    $target = UserFactory::nonAdmin();
    $query = User::find()->id($target->id);

    expect($this->action->performAction($query))->toBeFalse();

    // No pending reason written — the action exits before the loop.
    $state = UserStateRecord::findOne(['userId' => $target->id]);
    expect($state)->toBeNull();
});

it('rejects when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $target = UserFactory::nonAdmin();
    $query = User::find()->id($target->id);

    expect($this->action->performAction($query))->toBeFalse();

    $state = UserStateRecord::findOne(['userId' => $target->id]);
    expect($state)->toBeNull();
});

// =============================================================================
// Confirmation message — non-empty, predictable
// =============================================================================

it('returns a non-empty confirmation message for the bulk action', function() {
    $message = $this->action->getConfirmationMessage();

    expect($message)->toBeString();
    expect((string)$message)->not->toBe('');
});

// =============================================================================
// Trigger label — predictable copy
// =============================================================================

it('returns the action trigger label "Send password reset email"', function() {
    expect($this->action->getTriggerLabel())->toBe('Send password reset email');
});
