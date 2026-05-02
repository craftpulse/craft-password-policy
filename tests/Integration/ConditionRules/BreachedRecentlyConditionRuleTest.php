<?php
/**
 * Pest coverage for `BreachedRecentlyConditionRule`. Number-input rule
 * filtering users whose `passwordpolicy_user_state.lastBreachDetectedAt`
 * falls within the last N days.
 *
 * @link      https://craftpulse.com
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
