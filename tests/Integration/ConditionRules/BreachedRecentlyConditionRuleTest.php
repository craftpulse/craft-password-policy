<?php
/**
 * Pest coverage for `BreachedRecentlyConditionRule`. Number-input rule
 * filtering users whose `passwordpolicy_user_state.lastBreachDetectedAt`
 * falls within the last N days.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\conditions\BreachedRecentlyConditionRule;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// matchElement
// =============================================================================

it('matches a user whose breach detection is inside the window', function() {
    $user = UserFactory::admin();
    seedRecentBreach($user, Carbon::now('UTC')->subDays(3));

    $rule = new BreachedRecentlyConditionRule();
    $rule->value = '7';

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match a user whose breach detection is outside the window', function() {
    $user = UserFactory::admin();
    seedRecentBreach($user, Carbon::now('UTC')->subDays(60));

    $rule = new BreachedRecentlyConditionRule();
    $rule->value = '7';

    expect($rule->matchElement($user))->toBeFalse();
});

it('does not match a user with no breach state row', function() {
    $user = UserFactory::admin();

    $rule = new BreachedRecentlyConditionRule();
    $rule->value = '7';

    expect($rule->matchElement($user))->toBeFalse();
});

it('does not match anyone when window is zero or negative', function() {
    $user = UserFactory::admin();
    seedRecentBreach($user, Carbon::now('UTC'));

    $rule = new BreachedRecentlyConditionRule();
    $rule->value = '0';

    expect($rule->matchElement($user))->toBeFalse();
});

// =============================================================================
// modifyQuery
// =============================================================================

it('narrows User::find() to recently-breached users', function() {
    $recent = UserFactory::admin();
    seedRecentBreach($recent, Carbon::now('UTC')->subDays(2));

    $stale = UserFactory::admin();
    seedRecentBreach($stale, Carbon::now('UTC')->subDays(120));

    $clean = UserFactory::admin();

    $rule = new BreachedRecentlyConditionRule();
    $rule->value = '14';

    $query = User::find()->status(null);
    $rule->modifyQuery($query);
    $ids = $query->ids();

    expect($ids)->toContain($recent->id)
        ->and($ids)->not->toContain($stale->id)
        ->and($ids)->not->toContain($clean->id);
});

// =============================================================================
// F2 — naive-UTC parse must not shift by the ambient server timezone
// =============================================================================

it('does not falsely match a breach just outside the window on a non-UTC server', function() {
    // Regression: `Carbon::parse((string)$detectedAt)` without an explicit
    // timezone interprets the naive-UTC `lastBreachDetectedAt` string in
    // the AMBIENT process timezone. Pacific/Honolulu is a fixed UTC-10
    // (no DST, so the offset is deterministic) — under the bug, parsing a
    // naive UTC string there shifts the resolved instant ten hours LATER
    // (more recent) than intended, which can push a breach that's
    // genuinely outside the window back inside it.
    $originalTz = date_default_timezone_get();
    date_default_timezone_set('Pacific/Honolulu');

    try {
        $user = UserFactory::admin();
        // True instant: 7 days + 5 hours ago — five hours OUTSIDE a
        // 7-day window. The +10h bug shift would make this look only
        // ~-19h ago against the cutoff, i.e. inside the window.
        seedRecentBreach($user, Carbon::now('UTC')->subDays(7)->subHours(5));

        $rule = new BreachedRecentlyConditionRule();
        $rule->value = '7';

        expect($rule->matchElement($user))->toBeFalse();
    } finally {
        date_default_timezone_set($originalTz);
    }
});

it('still matches a breach genuinely inside the window on a non-UTC server', function() {
    $originalTz = date_default_timezone_get();
    date_default_timezone_set('Pacific/Honolulu');

    try {
        $user = UserFactory::admin();
        seedRecentBreach($user, Carbon::now('UTC')->subDays(2));

        $rule = new BreachedRecentlyConditionRule();
        $rule->value = '7';

        expect($rule->matchElement($user))->toBeTrue();
    } finally {
        date_default_timezone_set($originalTz);
    }
});

// =============================================================================
// Helpers
// =============================================================================

function seedRecentBreach(User $user, Carbon $detectedAt): void
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
