<?php
/**
 * Pest coverage for the F4 investigation into
 * `UserSecurityController::_getExpiryThreshold()`. Pins that the expiry
 * threshold used to compute `isExpired` on the Password Security tab
 * stays correct on a non-UTC server.
 *
 * Investigation note: unlike the F2 findings (`UserIndexService`,
 * `NotificationService`, `BreachedRecentlyConditionRule`), this method
 * does NOT parse a naive-UTC DB string — `$lastChange` is already
 * hydrated via `DateTimeHelper::toDateTime()` (line ~186), and
 * `_getExpiryThreshold()`'s `new DateTime('now')` represents the true
 * current absolute instant regardless of which timezone label PHP
 * attaches to it (no naive-string ambiguity — `'now'` isn't sourced
 * from the DB). PHP's `DateTime` comparison operators (`<`, `>=`, ...)
 * are timezone-aware: comparing two `DateTime` instances compares their
 * actual point in time, not their raw formatted strings, so
 * `$lastChange < $expiryThreshold` in `actionIndex()` stays correct even
 * when the two operands carry different timezone labels. This file pins
 * that correctness rather than "fixing" a bug that doesn't exist here.
 *
 * Pacific/Honolulu is used as the non-UTC fixture zone: it's a fixed
 * UTC-10 with no DST, so any latent shift would be deterministic
 * year-round.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\controllers\UserSecurityController;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    $this->settings->expiryAmount = 30;
    $this->settings->expiryPeriod = 'day';

    $this->controller = new UserSecurityController('user-security', PasswordPolicy::$plugin);

    $this->method = (new ReflectionClass(UserSecurityController::class))
        ->getMethod('_getExpiryThreshold');
    $this->method->setAccessible(true);
});

afterEach(function() {
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
});

// =============================================================================
// F4 — expiry-threshold comparisons stay correct on a non-UTC server
// =============================================================================

it('resolves an expiry threshold whose absolute instant matches the configured window on a non-UTC server', function() {
    $originalTz = date_default_timezone_get();
    date_default_timezone_set('Pacific/Honolulu');

    try {
        /** @var DateTime $threshold */
        $threshold = $this->method->invoke($this->controller);
        $utcNow = DateTimeHelper::currentUTCDateTime();
    } finally {
        date_default_timezone_set($originalTz);
    }

    $expectedTs = $utcNow->getTimestamp() - (30 * 86400);

    // Loose tolerance for test execution time between the two calls above;
    // a genuine ambient-timezone bug would be off by ten hours (36000s),
    // far outside this margin.
    expect($threshold->getTimestamp())->toBeGreaterThanOrEqual($expectedTs - 5)
        ->and($threshold->getTimestamp())->toBeLessThanOrEqual($expectedTs + 5);
});

it('correctly resolves isExpired-equivalent comparisons against a UTC-hydrated lastChange on a non-UTC server', function() {
    // Mirrors actionIndex()'s `$lastChange < $expiryThreshold` comparison
    // directly: a naive-UTC DB string hydrated via DateTimeHelper::toDateTime()
    // (as $lastChange genuinely is in actionIndex()) compared against
    // _getExpiryThreshold()'s result.
    $originalTz = date_default_timezone_get();
    date_default_timezone_set('Pacific/Honolulu');

    try {
        $expiryThreshold = $this->method->invoke($this->controller);

        // A naive UTC string 45 days ago — past the 30-day window, so this
        // must resolve as expired (lastChange < threshold).
        $expiredRaw = DateTimeHelper::currentUTCDateTime()->modify('-45 days')->format('Y-m-d H:i:s');
        $expiredLastChange = DateTimeHelper::toDateTime($expiredRaw);

        // A naive UTC string 5 days ago — comfortably inside the window,
        // so this must NOT resolve as expired.
        $freshRaw = DateTimeHelper::currentUTCDateTime()->modify('-5 days')->format('Y-m-d H:i:s');
        $freshLastChange = DateTimeHelper::toDateTime($freshRaw);
    } finally {
        date_default_timezone_set($originalTz);
    }

    expect($expiredLastChange)->toBeInstanceOf(DateTime::class);
    expect($freshLastChange)->toBeInstanceOf(DateTime::class);
    expect($expiredLastChange < $expiryThreshold)->toBeTrue();
    expect($freshLastChange < $expiryThreshold)->toBeFalse();
});
