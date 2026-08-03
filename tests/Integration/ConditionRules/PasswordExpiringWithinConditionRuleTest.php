<?php
/**
 * Pest coverage for `PasswordExpiringWithinConditionRule`. Pairs with
 * the existing `PasswordExpiredConditionRule` — both shipped knowingly
 * because operators reach for different ergonomics ("expired yes/no"
 * vs. "expiring within N days").
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
use craftpulse\passwordpolicy\elements\conditions\PasswordExpiringWithinConditionRule;
use craftpulse\passwordpolicy\PasswordPolicy;
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
// matchElement — in-memory boundary
// =============================================================================

it('matches a user whose change date is older than (now - expiry + window)', function() {
    $rule = new PasswordExpiringWithinConditionRule();
    $rule->value = '7';

    $user = UserFactory::admin();
    // 25 days old + 30-day expiry = 5 days from expiry → within 7-day window.
    $user->lastPasswordChangeDate = Carbon::now()->subDays(25)->toDateTime();

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match a user whose change is newer than the lookahead', function() {
    $rule = new PasswordExpiringWithinConditionRule();
    $rule->value = '7';

    $user = UserFactory::admin();
    // 5 days old + 30-day expiry = 25 days from expiry → outside 7-day window.
    $user->lastPasswordChangeDate = Carbon::now()->subDays(5)->toDateTime();

    expect($rule->matchElement($user))->toBeFalse();
});

it('matches users who have never changed their password', function() {
    $rule = new PasswordExpiringWithinConditionRule();
    $rule->value = '14';

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = null;

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match anyone when expiry is not configured', function() {
    $rule = new PasswordExpiringWithinConditionRule();
    $rule->value = '7';
    $this->settings->expiryAmount = null;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = Carbon::now()->subDays(60)->toDateTime();

    expect($rule->matchElement($user))->toBeFalse();
});

// =============================================================================
// matchElement — hydration for a freshly-loaded user
// =============================================================================

it('hydrates lastPasswordChangeDate from the DB for a freshly-loaded user', function() {
    $rule = new PasswordExpiringWithinConditionRule();
    $rule->value = '7';

    // 28 days old + 30-day expiry = 2 days from expiry → within the 7-day window.
    $user = UserFactory::admin();
    setLastChange($user, Carbon::now()->subDays(28));

    // Reload via the element query — UserQuery::beforePrepare() does NOT
    // select lastPasswordChangeDate, so the in-memory value is null. This is
    // the gap matchElement() must hydrate around; without the DB-scalar
    // hydration the rule would mis-classify every freshly-loaded user.
    /** @var User $reloaded */
    $reloaded = User::find()->id($user->id)->status(null)->one();
    expect($reloaded->lastPasswordChangeDate)->toBeNull();

    expect($rule->matchElement($reloaded))->toBeTrue();
});

// =============================================================================
// modifyQuery — SQL filter narrows the result set
// =============================================================================

it('narrows User::find() to expiring users', function() {
    $expiring = UserFactory::admin();
    setLastChange($expiring, Carbon::now()->subDays(28));

    $safe = UserFactory::admin();
    setLastChange($safe, Carbon::now()->subDays(2));

    $rule = new PasswordExpiringWithinConditionRule();
    $rule->value = '7';

    $query = User::find()->status(null);
    $rule->modifyQuery($query);
    $ids = $query->ids();

    expect($ids)->toContain($expiring->id)
        ->and($ids)->not->toContain($safe->id);
});

// =============================================================================
// Helpers
// =============================================================================

function setLastChange(User $user, Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $when->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}
