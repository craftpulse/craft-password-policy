<?php
/**
 * Pest coverage for `PasswordStatusConditionRule`. Multi-select rule
 * filtering users by the composite password-status badge value.
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
use craft\enums\CmsEdition;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\conditions\PasswordStatusConditionRule;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();
    $this->service = $this->plugin->getUserIndex();

    $this->originalEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->expiryAmount = 30;
    $this->settings->expiryPeriod = 'day';
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->edition = $this->originalCraftEdition;
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
    $this->service->resetCache();
});

// =============================================================================
// Options
// =============================================================================

it('exposes seven status options on Pro + Pro Craft', function() {
    Craft::$app->edition = CmsEdition::Pro;

    $rule = new PasswordStatusConditionRule();
    $reflection = new ReflectionClass($rule);
    $method = $reflection->getMethod('options');
    $method->setAccessible(true);

    expect($method->invoke($rule))->toHaveCount(7);
});

it('hides the policy_drift option on Solo Craft', function() {
    Craft::$app->edition = CmsEdition::Solo;

    $rule = new PasswordStatusConditionRule();
    $reflection = new ReflectionClass($rule);
    $method = $reflection->getMethod('options');
    $method->setAccessible(true);

    $options = $method->invoke($rule);

    expect($options)->not->toHaveKey(UserIndexService::STATUS_POLICY_DRIFT)
        ->and($options)->toHaveCount(6);
});

it('hides the policy_drift option on Lite plugin', function() {
    Craft::$app->edition = CmsEdition::Pro;
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $rule = new PasswordStatusConditionRule();
    $reflection = new ReflectionClass($rule);
    $method = $reflection->getMethod('options');
    $method->setAccessible(true);

    expect($method->invoke($rule))->not->toHaveKey(UserIndexService::STATUS_POLICY_DRIFT);
});

// =============================================================================
// matchElement
// =============================================================================

it('matches a user whose status is in the selected set', function() {
    Craft::$app->edition = CmsEdition::Pro;

    $user = UserFactory::admin();
    seedStatusLastChange($user, Carbon::now()->subDays(60));

    $rule = new PasswordStatusConditionRule();
    $rule->setValues([UserIndexService::STATUS_EXPIRED]);

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match a user whose status is outside the selected set', function() {
    Craft::$app->edition = CmsEdition::Pro;

    $user = UserFactory::admin();
    seedStatusLastChange($user, Carbon::now()->subDays(2));

    $rule = new PasswordStatusConditionRule();
    $rule->setValues([UserIndexService::STATUS_EXPIRED]);

    expect($rule->matchElement($user))->toBeFalse();
});

it('matches all users when no status is selected', function() {
    Craft::$app->edition = CmsEdition::Pro;

    $user = UserFactory::admin();

    $rule = new PasswordStatusConditionRule();
    $rule->setValues([]);

    expect($rule->matchElement($user))->toBeTrue();
});

// =============================================================================
// modifyQuery
// =============================================================================

it('narrows User::find() to users matching the selected statuses', function() {
    Craft::$app->edition = CmsEdition::Pro;

    $expired = UserFactory::admin();
    seedStatusLastChange($expired, Carbon::now()->subDays(60));

    $breached = UserFactory::admin();
    seedStatusLastChange($breached, Carbon::now()->subDays(2));
    seedStatusBreachState($breached, Carbon::now()->subDays(1));

    $okUser = UserFactory::admin();
    seedStatusLastChange($okUser, Carbon::now()->subDays(2));

    $rule = new PasswordStatusConditionRule();
    $rule->setValues([UserIndexService::STATUS_BREACHED]);

    $query = User::find()->status(null);
    $rule->modifyQuery($query);
    $ids = $query->ids();

    expect($ids)->toContain($breached->id)
        ->and($ids)->not->toContain($expired->id)
        ->and($ids)->not->toContain($okUser->id);
});

// =============================================================================
// Helpers
// =============================================================================

function seedStatusLastChange(User $user, Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $when->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}

function seedStatusBreachState(User $user, Carbon $detectedAt): void
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
