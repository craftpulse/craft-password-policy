<?php
/**
 * Pest coverage for the PER-USER force-reset seam on `RetentionService`:
 * `canForceResetUser()` (the peer-admin guard) and `forceResetForUser()` (the
 * write). Together they are the Pro capability that the universal mass path in
 * `requirePasswordReset()` does not cover: a named account, expired or not.
 *
 * The guard is asserted here as a predicate rather than only through the
 * surfaces that call it, because it is deliberately one shared gate. Three
 * surfaces consume it (the Password Security pane's flag, the POST handler on
 * `UserSecurityController`, and the `ForcePasswordReset` bulk element action) and
 * a duplicated authorization check drifts, with the copy that drifts being the
 * one nobody tests.
 *
 * The two paths differ in the pending reason they pin, and that difference is
 * load-bearing for the audit trail: the mass path says `ExpiryForced` because a
 * retention sweep reached the account, the per-user path says `AdminForceReset`
 * because an operator pointed at it.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getRetention();

    // Audit capture is universal across editions but operator-disableable, and
    // the parity assertion below reads the trail directly, so pin the flag on
    // rather than inheriting whatever an earlier file left behind.
    $this->settings = $this->plugin->getSettings();
    $this->originalEnableAuditLog = $this->settings->enableAuditLog;
    $this->settings->enableAuditLog = true;
});

afterEach(function() {
    $this->settings->enableAuditLog = $this->originalEnableAuditLog;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Reads `passwordResetRequired` straight out of the users table.
 * `craft\elements\db\UserQuery` doesn't select the column, so a re-fetched
 * element would always report `false`.
 */
function perUserResetFlagFor(int $userId): bool
{
    return (bool)(new Query())
        ->select(['passwordResetRequired'])
        ->from(Table::USERS)
        ->where(['id' => $userId])
        ->scalar();
}

// =============================================================================
// Peer-admin guard — the one shared gate
// =============================================================================

it('refuses a non-admin actor aiming at an admin target', function() {
    // The escalation the guard closes. `pp:user-force-reset` is grantable to
    // non-admins, so the permission alone must not carry "flag an
    // administrator's account and force a credential change on it".
    $actor = UserFactory::nonAdmin();
    $target = UserFactory::admin();

    expect($this->service->canForceResetUser($target, $actor))->toBeFalse();
});

it('allows a non-admin actor aiming at a non-admin target', function() {
    $actor = UserFactory::nonAdmin();
    $target = UserFactory::nonAdmin();

    expect($this->service->canForceResetUser($target, $actor))->toBeTrue();
});

it('allows an admin actor aiming at an admin target', function() {
    // Co-administrators are peers and Craft already treats them as mutually
    // trusted, so the guard is about crossing a privilege boundary rather than
    // about admin accounts being untouchable.
    $actor = UserFactory::admin();
    $target = UserFactory::admin();

    expect($this->service->canForceResetUser($target, $actor))->toBeTrue();
});

it('refuses when there is no identified actor', function() {
    $target = UserFactory::nonAdmin();

    expect($this->service->canForceResetUser($target, null))->toBeFalse();
});

// =============================================================================
// The write — flag, pending reason, audit event
// =============================================================================

it('flips the flag and pins AdminForceReset on the per-user path', function() {
    $target = UserFactory::nonAdmin();

    expect($this->service->forceResetForUser($target))->toBeTrue()
        ->and(perUserResetFlagFor((int)$target->id))->toBeTrue();

    $state = UserStateRecord::findOne(['userId' => $target->id]);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
});

it('reaches an admin target, unlike the mass path', function() {
    // The mass path skips admins outright, deliberately: a retention sweep
    // locking every administrator out at once is not a failure mode worth
    // introducing. An operator naming one admin account is a different act, and
    // the peer-admin guard is what decides whether they may.
    $target = UserFactory::admin();

    expect($this->service->forceResetForUser($target))->toBeTrue()
        ->and(perUserResetFlagFor((int)$target->id))->toBeTrue();
});

it('reports a no-op rather than re-pinning an already-flagged user', function() {
    // Re-pinning would clobber an in-flight pending reason (`BreachForced` from
    // HIBP-on-login, `ExpiryForced` from cron) with `AdminForceReset`, rewriting
    // why the user is being asked to change their password.
    $target = UserFactory::nonAdmin();
    $this->plugin->getUserState()->setPendingReason($target, ChangeReason::BreachForced);

    expect($this->service->forceResetForUser($target))->toBeTrue();

    // Second call finds the flag already set and declines to touch state.
    expect($this->service->forceResetForUser($target))->toBeFalse();

    $state = UserStateRecord::findOne(['userId' => $target->id]);

    expect($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
});

it('records the same password_reset_forced audit event the mass path records', function() {
    // Audit parity. Capture is universal across editions, and an operator
    // forcing a reset on a named account is exactly the kind of event a
    // compliance reviewer expects to find in the trail.
    $target = UserFactory::nonAdmin();

    $this->service->forceResetForUser($target);

    $event = (new Query())
        ->select(['event', 'outcome'])
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['userId' => $target->id, 'event' => 'password_reset_forced'])
        ->one();

    expect($event)->not->toBeNull()
        ->and($event['outcome'])->toBe('success');
});
