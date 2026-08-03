<?php
/**
 * Pest coverage for `PasswordResetRequiredConditionRule`.
 *
 * Regression target: `matchElement()` read `passwordResetRequired`,
 * which `UserQuery::beforePrepare()` does NOT addSelect — a freshly-
 * loaded User has it at its typed default (`false`) in memory regardless
 * of the column value. The pre-fix rule therefore NEVER matched on the
 * ON branch. The rule now hydrates the flag from a direct DB scalar
 * query, mirroring `PasswordExpiredConditionRule`'s date hydration.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\elements\conditions\PasswordResetRequiredConditionRule;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Helpers
// =============================================================================

function setPasswordResetRequired(User $user, bool $flag): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['passwordResetRequired' => $flag],
            ['id' => $user->id],
        )
        ->execute();
}

// =============================================================================
// matchElement — hydration on freshly-loaded users
// =============================================================================

it('matches a flagged user even when the in-memory prop is the default false', function() {
    // Pre-fix this asserted false (the rule read the default in-memory
    // prop). Post-fix the rule hydrates the real flag from the DB and
    // correctly returns true.
    $user = UserFactory::admin();
    setPasswordResetRequired($user, true);

    /** @var User $reloaded */
    $reloaded = User::find()->id($user->id)->one();

    // Sanity: the gap exists at the property level.
    expect($reloaded->passwordResetRequired)->toBeFalse();

    $rule = new PasswordResetRequiredConditionRule();
    $rule->value = true;

    expect($rule->matchElement($reloaded))->toBeTrue();
});

it('does not match an un-flagged user on the ON branch', function() {
    $user = UserFactory::admin();
    setPasswordResetRequired($user, false);

    /** @var User $reloaded */
    $reloaded = User::find()->id($user->id)->one();

    $rule = new PasswordResetRequiredConditionRule();
    $rule->value = true;

    expect($rule->matchElement($reloaded))->toBeFalse();
});

// =============================================================================
// matchElement — lightswitch off inverts
// =============================================================================

it('inverts cleanly when the lightswitch is off', function() {
    $flagged = UserFactory::admin();
    setPasswordResetRequired($flagged, true);

    /** @var User $reloadedFlagged */
    $reloadedFlagged = User::find()->id($flagged->id)->one();

    $rule = new PasswordResetRequiredConditionRule();
    $rule->value = false;

    // Flagged user, rule asks "is reset NOT required?" → false.
    expect($rule->matchElement($reloadedFlagged))->toBeFalse();

    $clean = UserFactory::admin();
    setPasswordResetRequired($clean, false);

    /** @var User $reloadedClean */
    $reloadedClean = User::find()->id($clean->id)->one();

    expect($rule->matchElement($reloadedClean))->toBeTrue();
});
