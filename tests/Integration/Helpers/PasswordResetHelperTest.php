<?php
/**
 * Pest coverage for `PasswordResetHelper::getAllUsersToExpire()`.
 *
 * Regression target: `_createInterval()` built an ISO-8601 duration
 * straight from `expiryAmount` with no floor guard. A `0` amount produced
 * `P0D` — an interval of zero — which would expire EVERY active user
 * immediately; a negative amount crashed `DateInterval`'s parse. The
 * helper now mirrors the guard in the condition rules / variable and
 * returns an empty list when expiry isn't meaningfully configured.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\helpers\PasswordResetHelper;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->settings = PasswordPolicy::$plugin->getSettings();
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;
    $this->settings->expiryPeriod = 'day';
});

afterEach(function() {
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
});

// =============================================================================
// getAllUsersToExpire — guard short-circuits
// =============================================================================

it('returns no users when expiryAmount is null', function() {
    $this->settings->expiryAmount = null;

    expect(PasswordResetHelper::getAllUsersToExpire())->toBe([]);
});

it('returns no users when expiryAmount is zero', function() {
    // Pre-fix this built `P0D` and would have swept every active user.
    $this->settings->expiryAmount = 0;

    expect(PasswordResetHelper::getAllUsersToExpire())->toBe([]);
});

it('returns no users when expiryAmount is negative', function() {
    // Pre-fix this crashed inside DateInterval's ISO-8601 parse.
    $this->settings->expiryAmount = -5;

    expect(PasswordResetHelper::getAllUsersToExpire())->toBe([]);
});
