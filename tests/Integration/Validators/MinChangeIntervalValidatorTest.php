<?php
/**
 * Pest coverage for `MinChangeIntervalValidator` — the "you changed your
 * password too recently" rule that blocks re-changing within N hours of
 * the last change (closes the history-cycling evasion).
 *
 * The validator reads `users.lastPasswordChangeDate` via a direct scalar
 * query (UserQuery doesn't select it), so tests seed the column straight
 * into the users table. Forced-reset bypass is driven through
 * `UserStateService::setPendingReason()` — the same source the central
 * history-write listener consumes.
 *
 * Resolution-hazard pin: the canonical regression asserts that a resolved
 * per-group interval enforces even when the global is 0 — re-reading the
 * global inside the validator would silently no-op the paid override.
 *
 * Settings + edition mutate during tests — `beforeEach` snapshots and
 * `afterEach` restores. The DB transaction wrapper handles row isolation.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\validators\MinChangeIntervalValidator;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->validator = new MinChangeIntervalValidator();
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalInterval = $this->settings->minChangeIntervalHours;

    // Pro + interval enabled is the default starting state.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->minChangeIntervalHours = 24;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->minChangeIntervalHours = $this->originalInterval;
});

// =============================================================================
// Helpers
// =============================================================================

function ppSetLastChange(User $user, Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $when->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}

// =============================================================================
// Window enforcement — blocks within, allows after
// =============================================================================

it('blocks a change within the interval window', function() {
    $user = UserFactory::admin();
    ppSetLastChange($user, Carbon::now('UTC')->subHours(2));

    $user->newPassword = 'BrandNewPassword99!';
    $this->validator->validateAttribute($user, 'newPassword');

    $errors = $user->getErrors('newPassword');

    expect($errors)->not->toBeEmpty()
        ->and($errors[0])->toContain('too recently');
});

it('allows a change once the interval window has elapsed', function() {
    $user = UserFactory::admin();
    ppSetLastChange($user, Carbon::now('UTC')->subHours(48));

    $user->newPassword = 'BrandNewPassword99!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

// =============================================================================
// Resolution hazard — resolved override enforces even when global is 0
// =============================================================================

it('enforces the resolved interval property over the global value', function() {
    // Global is OFF (0) — but a per-group policy resolves to 24h. The
    // validator must enforce the threaded property; re-reading the global
    // would silently bypass the paid per-group rule.
    $this->settings->minChangeIntervalHours = 0;

    $validator = new MinChangeIntervalValidator(['minChangeIntervalHours' => 24]);

    $user = UserFactory::admin();
    ppSetLastChange($user, Carbon::now('UTC')->subHours(2));

    $user->newPassword = 'BrandNewPassword99!';
    $validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->not->toBeEmpty();
});

// =============================================================================
// Forced-reset bypass — each forced ChangeReason exempts the change
// =============================================================================

it('bypasses the interval for each forced-reset reason', function(ChangeReason $reason) {
    $user = UserFactory::admin();
    ppSetLastChange($user, Carbon::now('UTC')->subHours(2));
    $this->plugin->getUserState()->setPendingReason($user, $reason);

    $user->newPassword = 'BrandNewPassword99!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
})->with([
    'admin force reset' => ChangeReason::AdminForceReset,
    'first login forced' => ChangeReason::FirstLoginForced,
    'expiry forced' => ChangeReason::ExpiryForced,
    'breach forced' => ChangeReason::BreachForced,
]);

it('still enforces the interval for a non-forced pending reason', function() {
    // A self-service pending reason is NOT a forced reset — the interval
    // applies. (Defensive: pins that the bypass list is exhaustive, not
    // "any pending reason exempts".)
    $user = UserFactory::admin();
    ppSetLastChange($user, Carbon::now('UTC')->subHours(2));
    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::SelfService);

    $user->newPassword = 'BrandNewPassword99!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->not->toBeEmpty();
});

// =============================================================================
// Feature gate — disabled at 0
// =============================================================================

it('returns early when the interval is zero', function() {
    $this->settings->minChangeIntervalHours = 0;

    $user = UserFactory::admin();
    ppSetLastChange($user, Carbon::now('UTC')->subHours(1));

    $user->newPassword = 'BrandNewPassword99!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

// =============================================================================
// Edge cases — never-changed user, empty password, new user
// =============================================================================

it('allows a never-changed user (null lastPasswordChangeDate)', function() {
    $user = UserFactory::admin();
    // No ppSetLastChange — the column stays null for a fresh user.

    $user->newPassword = 'BrandNewPassword99!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

it('returns early when the new password is empty', function() {
    $user = UserFactory::admin();
    ppSetLastChange($user, Carbon::now('UTC')->subHours(1));

    $user->newPassword = '';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

it('returns early on a user with no id (new user, never saved)', function() {
    $user = new User([
        'admin' => true,
        'username' => 'pending',
        'email' => 'pending@craftpulse.test',
    ]);

    $user->newPassword = 'whatever1!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});
