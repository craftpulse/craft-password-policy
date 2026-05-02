<?php
/**
 * Pest coverage for `LastChangeReasonConditionRule`. Multi-select rule
 * filtering users by the most-recent history row's `changeReason`.
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
use craftpulse\passwordpolicy\elements\conditions\LastChangeReasonConditionRule;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Options menu reflects the enum
// =============================================================================

it('exposes every ChangeReason case as a selectable option', function() {
    $rule = new LastChangeReasonConditionRule();

    $reflection = new ReflectionClass($rule);
    $method = $reflection->getMethod('options');
    $method->setAccessible(true);

    $options = $method->invoke($rule);

    foreach (ChangeReason::cases() as $case) {
        expect($options)->toHaveKey($case->value);
    }
});

// =============================================================================
// matchElement — in-memory query
// =============================================================================

it('matches a user whose latest history row matches the selected reason', function() {
    $user = UserFactory::admin();
    seedReasonHistory($user, ChangeReason::AdminForceReset, Carbon::now()->subSeconds(2));
    seedReasonHistory($user, ChangeReason::SelfService, Carbon::now());

    $rule = new LastChangeReasonConditionRule();
    $rule->setValues([ChangeReason::SelfService->value]);

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match a user whose latest reason is outside the selected set', function() {
    $user = UserFactory::admin();
    seedReasonHistory($user, ChangeReason::SelfService, Carbon::now());

    $rule = new LastChangeReasonConditionRule();
    $rule->setValues([ChangeReason::BreachForced->value]);

    expect($rule->matchElement($user))->toBeFalse();
});

it('does not match a user with no history rows', function() {
    $user = UserFactory::admin();

    $rule = new LastChangeReasonConditionRule();
    $rule->setValues([ChangeReason::SelfService->value]);

    expect($rule->matchElement($user))->toBeFalse();
});

it('matches all users when no reason is selected', function() {
    $user = UserFactory::admin();

    $rule = new LastChangeReasonConditionRule();
    $rule->setValues([]);

    expect($rule->matchElement($user))->toBeTrue();
});

// =============================================================================
// modifyQuery
// =============================================================================

it('narrows the query to users whose latest reason matches', function() {
    $hibpUser = UserFactory::admin();
    seedReasonHistory($hibpUser, ChangeReason::BreachForced, Carbon::now());

    $selfUser = UserFactory::admin();
    seedReasonHistory($selfUser, ChangeReason::SelfService, Carbon::now());

    $rule = new LastChangeReasonConditionRule();
    $rule->setValues([ChangeReason::BreachForced->value]);

    $query = User::find()->status(null);
    $rule->modifyQuery($query);
    $ids = $query->ids();

    expect($ids)->toContain($hibpUser->id)
        ->and($ids)->not->toContain($selfUser->id);
});

// =============================================================================
// Helpers
// =============================================================================

function seedReasonHistory(User $user, ChangeReason $reason, Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_password_history}}', [
            'userId' => $user->id,
            'passwordHash' => '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012',
            'changeReason' => $reason->value,
            'dateCreated' => $when->format('Y-m-d H:i:s'),
            'uid' => StringHelper::UUID(),
        ])
        ->execute();
}
