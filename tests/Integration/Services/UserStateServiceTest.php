<?php
/**
 * Pest coverage for `UserStateService` — the read/write surface over
 * `passwordpolicy_user_state`. The service is the single seam every
 * indirect change trigger writes through (HIBP-on-login,
 * `ForcePasswordReset` element action, retention/expiry, first-login
 * forced) and the central history-write listener consumes from. Tests
 * pin the unit-level behavior in isolation; cross-cutting "did the
 * listener consume the pending reason" assertions live in
 * `PasswordHistoryAuditContextTest`.
 *
 * The DB transaction wrapper handles per-test isolation; no afterEach
 * cleanup needed for the user_state rows.
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
    $this->service = $this->plugin->getUserState();
});

// =============================================================================
// getStateForUser — sparsely populated, null until first write
// =============================================================================

it('returns null for a user with no state row', function() {
    $user = UserFactory::admin();

    expect($this->service->getStateForUser($user))->toBeNull();
});

it('returns the persisted record after a write', function() {
    $user = UserFactory::admin();

    $this->service->setPendingReason($user, ChangeReason::AdminForceReset);

    $state = $this->service->getStateForUser($user);

    expect($state)->toBeInstanceOf(UserStateRecord::class)
        ->and($state->userId)->toBe($user->id)
        ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);
});

it('returns null when the user has no id (unsaved User instance)', function() {
    $user = new craft\elements\User();

    expect($this->service->getStateForUser($user))->toBeNull();
});

// =============================================================================
// setPendingReason — creates row if absent, updates if present
// =============================================================================

it('creates a state row on first setPendingReason write', function() {
    $user = UserFactory::admin();

    expect(UserStateRecord::findOne(['userId' => $user->id]))->toBeNull();

    $this->service->setPendingReason($user, ChangeReason::BreachForced);

    $record = UserStateRecord::findOne(['userId' => $user->id]);

    expect($record)->not->toBeNull()
        ->and($record->pendingResetReason)->toBe(ChangeReason::BreachForced->value)
        ->and($record->pendingResetSetAt)->not->toBeNull();
});

it('updates pendingResetReason on the existing row when called again', function() {
    $user = UserFactory::admin();

    $this->service->setPendingReason($user, ChangeReason::ExpiryForced);
    $this->service->setPendingReason($user, ChangeReason::AdminForceReset);

    $record = UserStateRecord::findOne(['userId' => $user->id]);

    expect($record->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value);

    // The second call must not create a duplicate row.
    $count = (new craft\db\Query())
        ->from(UserStateRecord::tableName())
        ->where(['userId' => $user->id])
        ->count();

    expect((int)$count)->toBe(1);
});

it('is a no-op for a user without an id', function() {
    $user = new craft\elements\User();

    $this->service->setPendingReason($user, ChangeReason::BreachForced);

    // No rows should land in the table.
    $count = (new craft\db\Query())
        ->from(UserStateRecord::tableName())
        ->count();

    expect((int)$count)->toBe(0);
});

// =============================================================================
// clearPendingReason — idempotent, no-op when no row
// =============================================================================

it('is a no-op when no row exists', function() {
    $user = UserFactory::admin();

    $this->service->clearPendingReason($user);

    expect(UserStateRecord::findOne(['userId' => $user->id]))->toBeNull();
});

it('clears the pending reason without deleting the row', function() {
    $user = UserFactory::admin();

    $this->service->setPendingReason($user, ChangeReason::BreachForced);
    $this->service->recordBreachCheck($user, true);

    $this->service->clearPendingReason($user);

    $record = UserStateRecord::findOne(['userId' => $user->id]);

    // Row stays — breach detection state is preserved across the consume.
    expect($record)->not->toBeNull()
        ->and($record->pendingResetReason)->toBeNull()
        ->and($record->pendingResetSetAt)->toBeNull()
        ->and($record->lastBreachDetectedAt)->not->toBeNull();
});

// =============================================================================
// recordBreachCheck — always lastCheckedAt, only detected updates lastDetected
// =============================================================================

it('updates lastBreachCheckAt on a clean check without setting lastBreachDetectedAt', function() {
    $user = UserFactory::admin();

    $this->service->recordBreachCheck($user, false);

    $record = UserStateRecord::findOne(['userId' => $user->id]);

    expect($record)->not->toBeNull()
        ->and($record->lastBreachCheckAt)->not->toBeNull()
        ->and($record->lastBreachDetectedAt)->toBeNull();
});

it('updates both timestamps on a detected check', function() {
    $user = UserFactory::admin();

    $this->service->recordBreachCheck($user, true);

    $record = UserStateRecord::findOne(['userId' => $user->id]);

    expect($record)->not->toBeNull()
        ->and($record->lastBreachCheckAt)->not->toBeNull()
        ->and($record->lastBreachDetectedAt)->not->toBeNull();
});

it('preserves pending reason when only recording a breach check', function() {
    // Mirrors the listener flow: setPendingReason() pins the cause, then
    // recordBreachCheck() updates the timestamps. The reason must survive
    // the second call so the central seam can consume it later.
    $user = UserFactory::admin();

    $this->service->setPendingReason($user, ChangeReason::BreachForced);
    $this->service->recordBreachCheck($user, true);

    $record = UserStateRecord::findOne(['userId' => $user->id]);

    expect($record->pendingResetReason)->toBe(ChangeReason::BreachForced->value);
});
