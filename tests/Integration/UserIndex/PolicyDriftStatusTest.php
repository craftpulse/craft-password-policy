<?php
/**
 * Pest coverage for the `policy_drift` status badge slot — gated to
 * Pro plugin + Craft Team or higher. The Lite-tier priority-order
 * tests in `StatusBadgePriorityTest.php` cover the six other states
 * exhaustively; this file focuses on drift detection because it
 * requires the broader test fixture (UserGroup, NamedPolicy, history
 * row with a snapshot column) that's only meaningful on Pro+.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\enums\CmsEdition;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup / teardown — pin Pro plugin + Pro Craft + per-group enabled
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getUserIndex();
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
    $this->originalEnablePerGroup = $this->settings->enablePerGroupPolicies;
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;
    $this->settings->enablePerGroupPolicies = true;

    // Pin a benign expiry config so expired/expiring don't dominate
    // the priority resolution. We want drift to surface.
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
// Drift resolution
// =============================================================================

it('resolves a user whose history snapshot differs from current policy as policy_drift', function() {
    $group = GroupFactory::create();
    PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    persistDriftGroupMembership($user, [$group->id]);

    // Recent change with stale snapshot ID — drift triggered.
    seedRecentChange($user);
    seedHistorySnapshot($user, '999999');

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_POLICY_DRIFT);
});

it('does not resolve drift when snapshot equals current policy', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    persistDriftGroupMembership($user, [$group->id]);

    seedRecentChange($user);
    seedHistorySnapshot($user, (string)$policy->id);

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->toBe(UserIndexService::STATUS_OK);
});

it('skips drift detection on Lite even when snapshot mismatches', function() {
    $group = GroupFactory::create();
    PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    persistDriftGroupMembership($user, [$group->id]);

    seedRecentChange($user);
    seedHistorySnapshot($user, '999999');

    // Drop to Lite — drift is not a state on Lite.
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->service->resetCache();
    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->not->toBe(UserIndexService::STATUS_POLICY_DRIFT);
});

it('skips drift detection on Solo Craft even when plugin is Pro', function() {
    $group = GroupFactory::create();
    PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    persistDriftGroupMembership($user, [$group->id]);

    seedRecentChange($user);
    seedHistorySnapshot($user, '999999');

    // The factory elevates Craft to Pro to create the group. Drop back
    // to Solo here — drift detection should now skip the resolver.
    Craft::$app->edition = CmsEdition::Solo;
    $this->service->resetCache();
    $this->service->preloadForUsers([$user->id]);

    expect($this->service->getStatusForUser($user))->not->toBe(UserIndexService::STATUS_POLICY_DRIFT);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Persists user group membership through Craft's `Users` service. See
 * `ProCellRenderingTest::persistGroupMembership()` for rationale —
 * different name to avoid Pest's cross-file global helper collision.
 */
function persistDriftGroupMembership(craft\elements\User $user, array $groupIds): void
{
    Craft::$app->getUsers()->assignUserToGroups($user->id, $groupIds);
}

function seedRecentChange(craft\elements\User $user): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => Carbon::now('UTC')->subDays(2)->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}

function seedHistorySnapshot(craft\elements\User $user, string $policySnapshot): void
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
