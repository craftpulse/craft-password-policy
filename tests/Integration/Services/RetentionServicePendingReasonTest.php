<?php
/**
 * Pest coverage for `RetentionService::requirePasswordReset()` — the
 * seam used by `PasswordResetJob` (cron-driven expiry),
 * `RetentionController::actionForceReset` (web-UI single-user trigger),
 * and `resetPasswordsByGroup()`. Phase D1.3 wired the service to
 * `UserStateService::setPendingReason(ExpiryForced)` so the user's
 * NEXT password change records the right `changeReason` in history.
 *
 * Admin-account guard stays the load-bearing safety net — the existing
 * pre-D1 contract (the free version never force-resets admins) must
 * apply to the pending-reason write too. Tests pin both branches.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

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
});

// =============================================================================
// Non-admin path — flag flips, ExpiryForced pinned
// =============================================================================

it('pins ExpiryForced pending reason on a non-admin force-reset', function() {
    // UserFactory::admin elevates to admin by default; build a non-admin
    // for this test so the service's `if (!$user->admin)` guard passes.
    $user = UserFactory::admin(['admin' => false]);

    $this->service->requirePasswordReset($user);

    $state = UserStateRecord::findOne(['userId' => $user->id]);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::ExpiryForced->value);
});

// =============================================================================
// Admin guard — the safety net never writes state for admins
// =============================================================================

it('does not write state for admin users (admin guard preserves)', function() {
    $admin = UserFactory::admin();

    $this->service->requirePasswordReset($admin);

    expect(UserStateRecord::findOne(['userId' => $admin->id]))->toBeNull();
});

// =============================================================================
// Existing pending reason — most-recent-wins (intentional)
// =============================================================================

it('overwrites a stale pending reason with the most recent trigger', function() {
    // Same user could be flagged by HIBP-on-login first, then by
    // expiry-cron later. Service writes are idempotent: each call wins.
    // The CONSUME path on next change reads whichever reason was last
    // pinned, which matches "report the most recent operator action".
    $user = UserFactory::admin(['admin' => false]);

    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::BreachForced);

    $this->service->requirePasswordReset($user);

    $state = UserStateRecord::findOne(['userId' => $user->id]);

    expect($state->pendingResetReason)->toBe(ChangeReason::ExpiryForced->value);
});
