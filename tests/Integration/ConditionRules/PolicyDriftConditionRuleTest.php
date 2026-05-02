<?php
/**
 * Pest coverage for `PolicyDriftConditionRule`. Lightswitch rule
 * filtering users whose history snapshot differs from the resolver's
 * current pick. Pro + Craft Team-or-better only — Solo and Lite gates
 * verified at the registration listener level (D2.1 / D2.2 EditionGatingTest).
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
use craft\enums\CmsEdition;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\conditions\PolicyDriftConditionRule;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup / teardown — Pro plugin + Pro Craft + per-group enabled
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();
    $this->service = $this->plugin->getUserIndex();

    $this->originalEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
    $this->originalEnablePerGroup = $this->settings->enablePerGroupPolicies;
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;
    $this->settings->enablePerGroupPolicies = true;
    // Benign expiry config so expired/expiring don't dominate priority.
    $this->settings->expiryAmount = 365;
    $this->settings->expiryPeriod = 'day';
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->edition = $this->originalCraftEdition;
    $this->settings->enablePerGroupPolicies = $this->originalEnablePerGroup;
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
    $this->service->resetCache();
});

// =============================================================================
// matchElement
// =============================================================================

it('matches a drifted user when value is on', function() {
    $group = GroupFactory::create();
    PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    Craft::$app->getUsers()->assignUserToGroups($user->id, [$group->id]);

    seedDriftLastChange($user, Carbon::now('UTC')->subDays(2));
    seedDriftHistory($user, '999999');

    $rule = new PolicyDriftConditionRule();
    $rule->value = true;

    expect($rule->matchElement($user))->toBeTrue();
});

it('does not match a non-drifted user when value is on', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    Craft::$app->getUsers()->assignUserToGroups($user->id, [$group->id]);

    seedDriftLastChange($user, Carbon::now('UTC')->subDays(2));
    seedDriftHistory($user, (string)$policy->id);

    $rule = new PolicyDriftConditionRule();
    $rule->value = true;

    expect($rule->matchElement($user))->toBeFalse();
});

it('matches a non-drifted user when value is off', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    Craft::$app->getUsers()->assignUserToGroups($user->id, [$group->id]);

    seedDriftLastChange($user, Carbon::now('UTC')->subDays(2));
    seedDriftHistory($user, (string)$policy->id);

    $rule = new PolicyDriftConditionRule();
    $rule->value = false;

    expect($rule->matchElement($user))->toBeTrue();
});

// =============================================================================
// modifyQuery
// =============================================================================

it('narrows User::find() to drifted users when on', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);

    $drifted = UserFactory::admin();
    Craft::$app->getUsers()->assignUserToGroups($drifted->id, [$group->id]);
    seedDriftLastChange($drifted, Carbon::now('UTC')->subDays(2));
    seedDriftHistory($drifted, '999999');

    $aligned = UserFactory::admin();
    Craft::$app->getUsers()->assignUserToGroups($aligned->id, [$group->id]);
    seedDriftLastChange($aligned, Carbon::now('UTC')->subDays(2));
    seedDriftHistory($aligned, (string)$policy->id);

    $rule = new PolicyDriftConditionRule();
    $rule->value = true;

    $query = User::find()->status(null);
    $rule->modifyQuery($query);
    $ids = $query->ids();

    expect($ids)->toContain($drifted->id)
        ->and($ids)->not->toContain($aligned->id);
});

// =============================================================================
// Helpers
// =============================================================================

function seedDriftLastChange(User $user, Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $when->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}

function seedDriftHistory(User $user, string $policySnapshot): void
{
    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_password_history}}', [
            'userId' => $user->id,
            'passwordHash' => '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012',
            'changeReason' => 'self_service',
            'policySnapshot' => $policySnapshot,
            'dateCreated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
            'uid' => StringHelper::UUID(),
        ])
        ->execute();
}
