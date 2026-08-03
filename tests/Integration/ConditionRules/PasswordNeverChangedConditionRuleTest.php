<?php
/**
 * Pest coverage for `PasswordNeverChangedConditionRule`.
 *
 * Regression target: `matchElement()` reads `lastPasswordChangeDate`,
 * which `UserQuery::beforePrepare()` does NOT addSelect — a freshly-
 * loaded User has it null in memory regardless of the column value. The
 * pre-fix rule treated EVERY user as "never changed." The rule now
 * hydrates the value from a direct DB scalar query, mirroring
 * `PasswordExpiredConditionRule`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\elements\conditions\PasswordNeverChangedConditionRule;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// matchElement — in-memory value present
// =============================================================================

it('matches a user whose lastPasswordChangeDate is null in memory', function() {
    $rule = new PasswordNeverChangedConditionRule();
    $rule->value = true;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = null;

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match a user with an in-memory change date', function() {
    $rule = new PasswordNeverChangedConditionRule();
    $rule->value = true;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = Carbon::now()->subDays(5)->toDateTime();

    expect($rule->matchElement($user))->toBeFalse();
});

// =============================================================================
// matchElement — hydration on freshly-loaded users
// =============================================================================

it('hydrates a changed user from the DB and does NOT match never-changed', function() {
    // Pre-fix this asserted true (the rule read the null in-memory prop
    // and concluded "never changed"). Post-fix the rule hydrates the real
    // value from the users table and correctly returns false.
    $user = UserFactory::admin();

    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => Carbon::now()->subDays(5)->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();

    /** @var User $reloaded */
    $reloaded = User::find()->id($user->id)->one();

    // Sanity: the gap exists at the property level.
    expect($reloaded->lastPasswordChangeDate)->toBeNull();

    $rule = new PasswordNeverChangedConditionRule();
    $rule->value = true;

    expect($rule->matchElement($reloaded))->toBeFalse();
});

it('hydrates a genuinely never-changed user as null and matches', function() {
    $user = UserFactory::admin();

    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => null],
            ['id' => $user->id],
        )
        ->execute();

    /** @var User $reloaded */
    $reloaded = User::find()->id($user->id)->one();

    $rule = new PasswordNeverChangedConditionRule();
    $rule->value = true;

    expect($rule->matchElement($reloaded))->toBeTrue();
});

// =============================================================================
// matchElement — lightswitch off inverts
// =============================================================================

it('inverts cleanly when the lightswitch is off', function() {
    $rule = new PasswordNeverChangedConditionRule();
    $rule->value = false;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = null;

    // Never-changed user, rule asks "has this user changed?" → false.
    expect($rule->matchElement($user))->toBeFalse();

    $user->lastPasswordChangeDate = Carbon::now()->subDays(5)->toDateTime();
    expect($rule->matchElement($user))->toBeTrue();
});
