<?php
/**
 * Pest coverage for `PasswordExpiredConditionRule`. Pairs with
 * `PasswordExpiringWithinConditionRuleTest` — both rules are exercised
 * the same way (settings-driven expiry threshold + per-user date
 * comparison), but `PasswordExpiredConditionRule` is the simpler
 * "expired yes/no" lightswitch.
 *
 * Particular focus: `matchElement()` on a freshly-loaded User. Memory
 * gap #9 means `UserQuery::beforePrepare()` does NOT addSelect
 * `lastPasswordChangeDate`, so `$user->lastPasswordChangeDate` is null
 * regardless of the column value. The rule hydrates from a direct DB
 * query at entry to `matchElement()`; the freshly-loaded path is the
 * regression-pre-fix surface and gets its own pinned test.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\elements\conditions\PasswordExpiredConditionRule;
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
// matchElement — value=true (lightswitch ON, "find expired")
// =============================================================================

it('matches a user whose change date predates the expiry threshold', function() {
    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;

    $user = UserFactory::admin();
    // 60 days old + 30-day expiry → expired by 30 days.
    $user->lastPasswordChangeDate = Carbon::now()->subDays(60)->toDateTime();

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match a user whose change date is within the expiry window', function() {
    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;

    $user = UserFactory::admin();
    // 5 days old + 30-day expiry → still 25 days from expiry.
    $user->lastPasswordChangeDate = Carbon::now()->subDays(5)->toDateTime();

    expect($rule->matchElement($user))->toBeFalse();
});

it('matches a user who has never changed their password', function() {
    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = null;

    // Documented behavior: never-changed === expired.
    expect($rule->matchElement($user))->toBeTrue();
});

// =============================================================================
// matchElement — value=false (lightswitch OFF, "find non-expired")
// =============================================================================

it('inverts cleanly when the lightswitch is off', function() {
    $expiredRule = new PasswordExpiredConditionRule();
    $expiredRule->value = false;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = Carbon::now()->subDays(60)->toDateTime();

    // Expired user, rule asks "is this user NOT expired?" → false.
    expect($expiredRule->matchElement($user))->toBeFalse();

    $user->lastPasswordChangeDate = Carbon::now()->subDays(5)->toDateTime();
    expect($expiredRule->matchElement($user))->toBeTrue();
});

// =============================================================================
// matchElement — settings short-circuit
// =============================================================================

it('does not match anyone when expiry is not configured (lightswitch on)', function() {
    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;
    $this->settings->expiryAmount = null;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = Carbon::now()->subDays(365)->toDateTime();

    // No threshold to compare against — nobody's expired.
    expect($rule->matchElement($user))->toBeFalse();
});

it('matches everyone when expiry is not configured (lightswitch off)', function() {
    $rule = new PasswordExpiredConditionRule();
    $rule->value = false;
    $this->settings->expiryAmount = null;

    $user = UserFactory::admin();
    $user->lastPasswordChangeDate = Carbon::now()->subDays(365)->toDateTime();

    // No threshold, "find non-expired" matches every user.
    expect($rule->matchElement($user))->toBeTrue();
});

// =============================================================================
// matchElement — hydration on freshly-loaded users
// =============================================================================

it('hydrates lastPasswordChangeDate from the DB on a freshly-loaded user', function() {
    // The fix's regression target: a User loaded via the standard query
    // path has `lastPasswordChangeDate = null` in memory because
    // `UserQuery::beforePrepare()` doesn't addSelect the column. The
    // rule hydrates from a direct DB query at entry to `matchElement()`,
    // so the comparison runs against the real value. Pre-fix, this same
    // test would assert `false` because the rule would treat the user
    // as "never changed" → expired → matches → true. Post-fix, the user
    // IS in fact within the 30-day window and the rule returns false.
    $user = UserFactory::admin();
    $expectedChange = Carbon::now()->subDays(5);

    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $expectedChange->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();

    /** @var User $reloaded */
    $reloaded = User::find()->id($user->id)->one();

    // Sanity: confirm the gap exists at the property level. Pre-fix the
    // rule would have read this null and concluded "never changed".
    expect($reloaded->lastPasswordChangeDate)->toBeNull();

    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;

    // Hydration path takes over — within the 30-day window, not expired.
    expect($rule->matchElement($reloaded))->toBeFalse();
});

it('hydrates a never-changed user as null and treats them as expired', function() {
    // Belt-and-braces: the freshly-loaded path also handles the genuine
    // "no row value" case — the column is null in the DB, the rule
    // hydrates null, and the never-changed branch fires.
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
    expect($reloaded->lastPasswordChangeDate)->toBeNull();

    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;

    expect($rule->matchElement($reloaded))->toBeTrue();
});

// =============================================================================
// modifyQuery — SQL filter narrows the result set
// =============================================================================

it('narrows User::find() to expired users via SQL', function() {
    $expired = UserFactory::admin();
    setLastPasswordChange($expired, Carbon::now()->subDays(60));

    $fresh = UserFactory::admin();
    setLastPasswordChange($fresh, Carbon::now()->subDays(5));

    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;

    $query = User::find()->status(null);
    $rule->modifyQuery($query);
    $ids = $query->ids();

    expect($ids)->toContain($expired->id)
        ->and($ids)->not->toContain($fresh->id);
});

it('includes never-changed users in the expired SQL filter', function() {
    // Finding 2: `matchElement()` treats a null change date as expired,
    // but a bare `lastPasswordChangeDate < date` SQL predicate evaluates
    // `NULL < date` to NULL (not true), silently dropping never-changed
    // users from the index query. The ON branch now ORs in an explicit
    // `IS NULL` clause so the two paths agree.
    $expired = UserFactory::admin();
    setLastPasswordChange($expired, Carbon::now()->subDays(60));

    $never = UserFactory::admin();
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => null],
            ['id' => $never->id],
        )
        ->execute();

    $fresh = UserFactory::admin();
    setLastPasswordChange($fresh, Carbon::now()->subDays(5));

    $rule = new PasswordExpiredConditionRule();
    $rule->value = true;

    $query = User::find()->status(null);
    $rule->modifyQuery($query);
    $ids = $query->ids();

    expect($ids)->toContain($expired->id)
        ->and($ids)->toContain($never->id)
        ->and($ids)->not->toContain($fresh->id);
});

// =============================================================================
// Helpers
// =============================================================================

function setLastPasswordChange(User $user, Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $when->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}
