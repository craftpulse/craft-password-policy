<?php
/**
 * Pest coverage for the composite status badge's priority order.
 *
 * `UserIndexService::getStatusForUser()` resolves a user's status by
 * walking seven possible states in a fixed order, returning the first
 * match. This file pins each transition: when multiple states could
 * apply, the higher-priority one wins.
 *
 * Priority (high → low): breached → expired → reset_required →
 * policy_drift → expiring → never_changed → ok.
 *
 * Tests for the Pro-only `policy_drift` state live in the D2.2
 * extensions; this file covers the Lite-tier subset and the priority
 * resolution between those.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getUserIndex();
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->expiryAmount = 30;
    $this->settings->expiryPeriod = 'day';
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
    $this->service->resetCache();
});

// =============================================================================
// Status order constant exposes the canonical priority list
// =============================================================================

it('exposes the seven status codes in priority order', function() {
    expect(UserIndexService::STATUS_ORDER)->toEqual([
        UserIndexService::STATUS_BREACHED,
        UserIndexService::STATUS_EXPIRED,
        UserIndexService::STATUS_RESET_REQUIRED,
        UserIndexService::STATUS_POLICY_DRIFT,
        UserIndexService::STATUS_EXPIRING,
        UserIndexService::STATUS_NEVER_CHANGED,
        UserIndexService::STATUS_OK,
    ]);
});

// =============================================================================
// Single-state resolutions
// =============================================================================

it('resolves a clean user as OK', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(5));

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_OK);
});

it('resolves a user with no history as never_changed', function() {
    $user = UserFactory::admin();

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_NEVER_CHANGED);
});

it('resolves a user inside the seven-day soon window as expiring', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(28));

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_EXPIRING);
});

it('resolves a user past the expiry threshold as expired', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(60));

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_EXPIRED);
});

it('resolves a user with passwordResetRequired as reset_required', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(2));
    seedResetRequiredRow($user, true);

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_RESET_REQUIRED);
});

it('resolves a user with a recent breach detection as breached', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(2));
    seedBreachRow($user, Carbon::now('UTC')->subDays(1));

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_BREACHED);
});

// =============================================================================
// Priority transitions
// =============================================================================

it('prefers breached over expired', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(60));
    seedBreachRow($user, Carbon::now('UTC')->subDays(1));

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_BREACHED);
});

it('prefers breached over reset_required', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(2));
    seedResetRequiredRow($user, true);
    seedBreachRow($user, Carbon::now('UTC')->subDays(3));

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_BREACHED);
});

it('prefers expired over reset_required', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(60));
    seedResetRequiredRow($user, true);

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_EXPIRED);
});

it('prefers reset_required over expiring', function() {
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(28));
    seedResetRequiredRow($user, true);

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_RESET_REQUIRED);
});

it('falls through to expired-over-breached when the breach is outside the recent window', function() {
    // 100-day-old breach detection — past the 90-day BREACHED_RECENT_DAYS
    // threshold — should NOT contribute to the badge anymore. Expired wins.
    $user = UserFactory::admin();
    seedLastChangeRow($user, Carbon::now('UTC')->subDays(60));
    seedBreachRow($user, Carbon::now('UTC')->subDays(100));

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_EXPIRED);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * @param Carbon|null $when
 */
function seedLastChangeRow(craft\elements\User $user, ?Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $when?->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}

function seedResetRequiredRow(craft\elements\User $user, bool $value): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['passwordResetRequired' => $value ? 1 : 0],
            ['id' => $user->id],
        )
        ->execute();
}

function seedBreachRow(craft\elements\User $user, Carbon $detectedAt): void
{
    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_user_state}}', [
            'userId' => $user->id,
            'lastBreachDetectedAt' => $detectedAt->format('Y-m-d H:i:s'),
            'lastBreachCheckAt' => $detectedAt->format('Y-m-d H:i:s'),
            'uid' => StringHelper::UUID(),
        ])
        ->execute();
}
