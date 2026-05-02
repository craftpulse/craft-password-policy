<?php
/**
 * Pest coverage for the Pro-tier cell renderers — breached,
 * policyDrift, and groupPolicies. The breached cell ships on Pro +
 * any Craft edition; the two policy cells require Pro + Craft Team
 * or higher.
 *
 * `CellRenderingTest.php` covers the six Lite-tier renderers; this
 * file pins the additional three so the gating matrix has full per-
 * column coverage. Tests that depend on `Craft::$app->edition`
 * mutate the value directly per memory gap #17 and restore in
 * `afterEach`.
 *
 * @link      https://craftpulse.com
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
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getUserIndex();
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
    $this->originalEnablePerGroup = $this->settings->enablePerGroupPolicies;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->edition = CmsEdition::Pro;
    $this->settings->enablePerGroupPolicies = true;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->edition = $this->originalCraftEdition;
    $this->settings->enablePerGroupPolicies = $this->originalEnablePerGroup;
    $this->service->resetCache();
});

// =============================================================================
// Breached cell
// =============================================================================

it('renders the breached cell as muted No when no detection has run', function() {
    $user = UserFactory::admin();

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_BREACHED);

    expect($html)
        ->toContain('class="status"')
        ->and($html)->toContain('No');
});

it('renders the breached cell red with a relative-time suffix when set', function() {
    $user = UserFactory::admin();
    seedBreachState($user, Carbon::now('UTC')->subDays(3));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_BREACHED);

    expect($html)
        ->toContain('status red')
        ->and($html)->toContain('Yes');
});

it('still renders the breached cell red even after the 90-day recent window', function() {
    // Operators want the full breach history visible on the column,
    // not gated by recency. The status badge is gated; the column is not.
    $user = UserFactory::admin();
    seedBreachState($user, Carbon::now('UTC')->subDays(180));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_BREACHED);

    expect($html)->toContain('status red');
});

// =============================================================================
// Policy drift cell
// =============================================================================

it('renders the policy drift cell as muted No when snapshot matches current', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    persistGroupMembership($user, [$group->id]);

    seedHistoryWithSnapshot($user, (string)$policy->id);

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_POLICY_DRIFT);

    expect($html)
        ->toContain('class="status"')
        ->and($html)->toContain('No');
});

it('renders the policy drift cell orange when snapshot differs from current', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    persistGroupMembership($user, [$group->id]);

    // History snapshot points at a stale policy ID different from the
    // currently-resolved one. Drift is true.
    seedHistoryWithSnapshot($user, '999999');

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_POLICY_DRIFT);

    expect($html)->toContain('status orange')
        ->and($html)->toContain('current')
        ->and($html)->toContain((string)$policy->id);
});

// =============================================================================
// Applied policies cell
// =============================================================================

it('renders the applied policies cell as muted dash when user has no policies', function() {
    $user = UserFactory::admin();

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_GROUP_POLICIES);

    expect($html)->toContain('—');
});

it('renders the applied policies cell as a comma-separated name list', function() {
    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    $nist = PolicyFactory::nist([$editors]);
    $owasp = PolicyFactory::owasp([$managers]);

    $user = UserFactory::admin();
    persistGroupMembership($user, [$editors->id, $managers->id]);

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_GROUP_POLICIES);

    expect($html)
        ->toContain($nist->name)
        ->and($html)->toContain($owasp->name);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Persists user group membership through Craft's `Users` service so
 * the resolver's `User::find()->id($id)->one()` round-trip in the
 * preloader sees the assignment. `User::setGroups()` alone caches the
 * groups in-memory on the original element instance, but our preload
 * issues a fresh query — fresh users have empty `_groups` until the
 * junction table is populated.
 */
function persistGroupMembership(craft\elements\User $user, array $groupIds): void
{
    Craft::$app->getUsers()->assignUserToGroups($user->id, $groupIds);
}

function seedBreachState(craft\elements\User $user, Carbon $detectedAt): void
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

function seedHistoryWithSnapshot(craft\elements\User $user, string $policySnapshot): void
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
