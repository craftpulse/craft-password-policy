<?php
/**
 * Pest coverage for the F2 timezone-cluster fix: `UserIndexService`
 * hydrates `users.lastPasswordChangeDate` / `lastBreachDetectedAt` (naive
 * UTC strings) via `_toDateTime()`. Parsing without an explicit UTC zone
 * assumes the AMBIENT process timezone (`system.timeZone`), shifting
 * every comparison against `now` (expired/expiring thresholds, breached-
 * recent window, `daysUntilExpiry`) by the full offset on a non-UTC
 * server.
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
// F2 — daysUntilExpiry must not shift by the ambient server timezone
// =============================================================================

it('computes the same daysUntilExpiry on a non-UTC server as on UTC', function() {
    $user = UserFactory::admin();

    // True instant: 30 days minus 20 hours ago — 20 hours of the expiry
    // window genuinely remain, which floors to 0 days remaining. Under the
    // bug, `_toDateTime()` parsing this naive UTC string as Pacific/Honolulu
    // (UTC-10) resolves an instant ten hours LATER than intended, pushing
    // the apparent remaining time to 30 hours — a full day over the
    // 24-hour floor boundary, flipping the result from 0 to 1.
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
        $this->service->preloadForUsers([$user->id]);
        $flags = $this->service->getStatusFlagsForUser($user);
    } finally {
        date_default_timezone_set($originalTz);
    }

    expect($flags['daysUntilExpiry'])->toBe(0);
});

it('resolves the expired/expiring boundary identically on a non-UTC server', function() {
    $user = UserFactory::admin();

    // True instant: comfortably past the 30-day threshold (45 days ago).
    // A +10h bug shift wouldn't be enough to flip this case on its own,
    // but pins that EXPIRED still resolves correctly under the same
    // non-UTC fixture the boundary test above exercises.
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
        $this->service->preloadForUsers([$user->id]);
        $status = $this->service->getStatusForUser($user);
    } finally {
        date_default_timezone_set($originalTz);
    }

    expect($status)->toBe(\craftpulse\passwordpolicy\services\UserIndexService::STATUS_EXPIRED);
});
