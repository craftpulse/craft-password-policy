<?php
/**
 * Pest coverage for the F2 timezone-cluster fix:
 * `NotificationService::_estimateDaysUntilExpiry()` hydrates
 * `users.lastPasswordChangeDate` (a naive UTC string) via
 * `DateTimeHelper::toDateTime()`. The pre-fix code used a bare
 * `new DateTime($lastChangeRaw)`, which assumes the AMBIENT process
 * timezone (`system.timeZone`) rather than UTC, shifting the resolved
 * `daysUntilExpiry` an expiry-reminder resend recomputes.
 *
 * Pacific/Honolulu is used as the non-UTC fixture zone: it's a fixed
 * UTC-10 with no DST, so the induced shift is deterministic year-round.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\NotificationService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

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
});

afterEach(function() {
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
});

// =============================================================================
// Helpers
// =============================================================================

function invokeEstimateDaysUntilExpiry(NotificationService $service, craft\elements\User $user): int
{
    $method = (new ReflectionClass($service))->getMethod('_estimateDaysUntilExpiry');

    return (int)$method->invoke($service, $user);
}

// =============================================================================
// F2 — daysUntilExpiry must not shift by the ambient server timezone
// =============================================================================

it('computes the same daysUntilExpiry on a non-UTC server as on UTC', function() {
    $user = UserFactory::admin();

    // True instant: 30 days minus 20 hours ago — 20 hours of the expiry
    // window genuinely remain, which floors to 0 days remaining. Under the
    // bug, a bare `new DateTime($lastChangeRaw)` parsing this naive UTC
    // string as Pacific/Honolulu (UTC-10) resolves an instant ten hours
    // LATER than intended, pushing the apparent remaining time to 30
    // hours — a full day over the 24-hour floor boundary, flipping the
    // result from 0 to 1.
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => Carbon::now('UTC')->subDays(30)->addHours(20)->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();

    $originalTz = date_default_timezone_get();
    date_default_timezone_set('Pacific/Honolulu');

    try {
        $days = invokeEstimateDaysUntilExpiry($this->plugin->getNotification(), $user);
    } finally {
        date_default_timezone_set($originalTz);
    }

    expect($days)->toBe(0);
});

it('returns 0 (not a negative count) once genuinely past expiry, on a non-UTC server', function() {
    $user = UserFactory::admin();

    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => Carbon::now('UTC')->subDays(45)->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();

    $originalTz = date_default_timezone_get();
    date_default_timezone_set('Pacific/Honolulu');

    try {
        $days = invokeEstimateDaysUntilExpiry($this->plugin->getNotification(), $user);
    } finally {
        date_default_timezone_set($originalTz);
    }

    expect($days)->toBe(0);
});
