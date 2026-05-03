<?php
/**
 * Pest coverage for `PolicyResolverService::resolveForUser()` — the
 * cross-policy merge that turns a (User, global settings, per-group
 * policies) tuple into the effective `SettingsModel` the validators
 * read at password-change time. The resolver stitches together the
 * boolean tri-state pre-pass (Option A — see `reference.md` § 6.3)
 * with `GroupPolicyModel::mergeWithGlobal()`'s non-boolean merge,
 * then auto-corrects the `maxLength` cap when a per-group `minLength`
 * bumps above the global.
 *
 * Each test mutates `Craft::$app->edition` (for Pro user-groups),
 * `$plugin->edition` (for the resolver's own gate), and the live
 * `SettingsModel` properties — `beforeEach` snapshots and `afterEach`
 * restores. The DB transaction wrapper keeps the policy/group rows
 * isolated.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\models\GroupPolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->resolver = $this->plugin->getPolicyResolver();
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnablePerGroup = $this->settings->enablePerGroupPolicies;
    $this->originalMinLength = $this->settings->minLength;
    $this->originalMaxLength = $this->settings->maxLength;
    $this->originalCases = $this->settings->cases;
    $this->originalNumbers = $this->settings->numbers;
    $this->originalSymbols = $this->settings->symbols;
    $this->originalHibp = $this->settings->hibp;

    // Resolver tests run against Pro by default (the gate blocks Lite).
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->enablePerGroupPolicies = true;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->enablePerGroupPolicies = $this->originalEnablePerGroup;
    $this->settings->minLength = $this->originalMinLength;
    $this->settings->maxLength = $this->originalMaxLength;
    $this->settings->cases = $this->originalCases;
    $this->settings->numbers = $this->originalNumbers;
    $this->settings->symbols = $this->originalSymbols;
    $this->settings->hibp = $this->originalHibp;
});

// =============================================================================
// Edition gate — Lite always returns global
// =============================================================================

it('returns global settings on Lite regardless of group policies', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->settings->minLength = 8;

    $group = GroupFactory::create();
    PolicyFactory::custom(['minLength' => 16], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(8)
        ->and($resolved)->toBe($this->settings); // same instance — no clone
});

// =============================================================================
// Per-group toggle gate — disabled means global wins
// =============================================================================

it('returns global settings when enablePerGroupPolicies is false', function() {
    $this->settings->enablePerGroupPolicies = false;
    $this->settings->minLength = 8;

    $group = GroupFactory::create();
    PolicyFactory::custom(['minLength' => 16], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(8);
});

// =============================================================================
// Group-membership shortcuts — no groups, no applicable policies
// =============================================================================

it('returns global settings for a user with no groups', function() {
    $this->settings->minLength = 10;

    $user = UserFactory::admin();
    // No setGroups call — admin user with empty groups.

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(10);
});

it('returns global settings when groups exist but none have a policy', function() {
    $this->settings->minLength = 10;

    $group = GroupFactory::create();
    // No PolicyFactory call — group has no policy assignment.

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(10);
});

// =============================================================================
// Single-group merge — group policy wins on more-restrictive fields
// =============================================================================

it('applies a single group policy on top of the global', function() {
    $this->settings->minLength = 8;
    $this->settings->cases = false;

    $group = GroupFactory::create();
    PolicyFactory::custom([
        'minLength' => 12,
        'cases' => true,
    ], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(12)
        ->and($resolved->cases)->toBeTrue();
});

it('applies a NIST preset policy', function() {
    $this->settings->minLength = 6;

    $group = GroupFactory::create();
    PolicyFactory::nist([$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    // NIST sets minLength=15 (Rev. 4), hibp=true, cases=false, numbers=false, symbols=false.
    expect($resolved->minLength)->toBe(15)
        ->and($resolved->hibp)->toBeTrue();
});

// =============================================================================
// Multi-group merge — most-restrictive wins per field
// =============================================================================

it('merges integer minimums across multiple groups (max wins)', function() {
    $this->settings->minLength = 6;
    $this->settings->passwordHistoryCount = 1;

    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    PolicyFactory::custom([
        'minLength' => 10,
        'passwordHistoryCount' => 5,
    ], [$editors]);
    PolicyFactory::custom([
        'minLength' => 14,
        'passwordHistoryCount' => 3,
    ], [$managers]);

    $user = UserFactory::admin();
    $user->setGroups([$editors, $managers]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(14)
        ->and($resolved->passwordHistoryCount)->toBe(5);
});

it('merges integer maximums across multiple groups (lowest non-zero wins)', function() {
    $this->settings->maxLength = 256;

    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    PolicyFactory::custom(['maxLength' => 128], [$editors]);
    PolicyFactory::custom(['maxLength' => 64], [$managers]);

    $user = UserFactory::admin();
    $user->setGroups([$editors, $managers]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->maxLength)->toBe(64);
});

it('merges expiration across mixed periods (shortest wins)', function() {
    $this->settings->expiryAmount = 365;
    $this->settings->expiryPeriod = 'day';

    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    PolicyFactory::custom([
        'expiryAmount' => 6,
        'expiryPeriod' => 'month',
    ], [$editors]);
    PolicyFactory::custom([
        'expiryAmount' => 90,
        'expiryPeriod' => 'day',
    ], [$managers]);

    $user = UserFactory::admin();
    $user->setGroups([$editors, $managers]);

    $resolved = $this->resolver->resolveForUser($user);

    // 90 days < 6 months (≈180 days) — managers' policy wins.
    expect($resolved->expiryAmount)->toBe(90)
        ->and($resolved->expiryPeriod)->toBe('day');
});

// =============================================================================
// Boolean tri-state — Option A semantics (any explicit true wins)
// =============================================================================

it('applies cross-policy true-wins for boolean override fields', function() {
    $this->settings->cases = false;

    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    // editors explicitly OFF, managers explicitly ON. Option A: ON wins.
    PolicyFactory::custom(['cases' => false], [$editors]);
    PolicyFactory::custom(['cases' => true], [$managers]);

    $user = UserFactory::admin();
    $user->setGroups([$editors, $managers]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->cases)->toBeTrue();
});

it('applies single-group explicit false against global true', function() {
    // Single-group exemption: when no other policy says true, the
    // group's explicit false is honored against the global true.
    $this->settings->cases = true;

    $group = GroupFactory::create();
    PolicyFactory::custom(['cases' => false], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->cases)->toBeFalse();
});

it('keeps global value when no policy sets the boolean explicitly', function() {
    $this->settings->numbers = true;

    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    // Both policies leave `numbers` null — global passes through.
    PolicyFactory::custom(['minLength' => 12], [$editors]);
    PolicyFactory::custom(['cases' => true], [$managers]);

    $user = UserFactory::admin();
    $user->setGroups([$editors, $managers]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->numbers)->toBeTrue();
});

it('resolves every boolean override field via cross-policy pre-pass', function(string $field) {
    // Matrix pin — for each of the 8 boolean fields, two policies with
    // opposite explicit values resolve to true (the "any true wins"
    // contract). Catches a regression where any one field gets dropped
    // from the resolver pre-pass.
    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    PolicyFactory::custom([$field => false], [$editors]);
    PolicyFactory::custom([$field => true], [$managers]);

    $user = UserFactory::admin();
    $user->setGroups([$editors, $managers]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->{$field})->toBeTrue();
})->with(GroupPolicyModel::booleanOverrideFields());

// =============================================================================
// Auto-correction — maxLength < minLength after merge drops the cap
// =============================================================================

it('drops maxLength when a per-group minLength forces it below the cap', function() {
    // Global says max 12, group says min 16 — merge would produce
    // max=12 / min=16 which is unsatisfiable. Auto-correction sets
    // maxLength=0 (no cap) so the minLength can be honored.
    $this->settings->minLength = 6;
    $this->settings->maxLength = 12;

    $group = GroupFactory::create();
    PolicyFactory::custom(['minLength' => 16], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(16)
        ->and($resolved->maxLength)->toBe(0);
});

it('keeps maxLength when minLength stays below it after merge', function() {
    $this->settings->minLength = 6;
    $this->settings->maxLength = 64;

    $group = GroupFactory::create();
    PolicyFactory::custom(['minLength' => 12], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(12)
        ->and($resolved->maxLength)->toBe(64);
});

it('drops maxLength even when both come from the group merge', function() {
    // Group A bumps minLength to 24, Group B caps maxLength at 16 — the
    // merged shape has min > max; auto-correction kicks in.
    $this->settings->minLength = 6;
    $this->settings->maxLength = 0; // no global cap

    $editors = GroupFactory::editors();
    $managers = GroupFactory::managers();

    PolicyFactory::custom(['minLength' => 24], [$editors]);
    PolicyFactory::custom(['maxLength' => 16], [$managers]);

    $user = UserFactory::admin();
    $user->setGroups([$editors, $managers]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved->minLength)->toBe(24)
        ->and($resolved->maxLength)->toBe(0);
});

// =============================================================================
// Equivalent-value codification — divergence indicator alignment
// =============================================================================

it('produces the same effective policy whether group repeats the global or not', function() {
    // PolicyController surfaces a "divergence indicator" that compares
    // group fields against the merged global. Two groups — one explicitly
    // setting cases=true (matching global), one leaving it null — should
    // produce identical resolved settings. Pin the contract.
    $this->settings->cases = true;
    $this->settings->minLength = 8;

    $group1 = GroupFactory::create();
    $group2 = GroupFactory::create();

    // Group A explicitly repeats global cases=true.
    PolicyFactory::custom(['minLength' => 10, 'cases' => true], [$group1]);
    // Group B leaves cases null (inherits).
    PolicyFactory::custom(['minLength' => 10], [$group2]);

    $userA = UserFactory::admin();
    $userA->setGroups([$group1]);
    $userB = UserFactory::admin();
    $userB->setGroups([$group2]);

    $resolvedA = $this->resolver->resolveForUser($userA);
    $resolvedB = $this->resolver->resolveForUser($userB);

    expect($resolvedA->cases)->toBe($resolvedB->cases)
        ->and($resolvedA->minLength)->toBe($resolvedB->minLength);
});

// =============================================================================
// Lifecycle — resolver does NOT mutate the global settings instance
// =============================================================================

it('does not mutate the global settings model', function() {
    $this->settings->minLength = 8;

    $group = GroupFactory::create();
    PolicyFactory::custom(['minLength' => 16], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $this->resolver->resolveForUser($user);

    // The live SettingsModel still reads minLength=8.
    expect($this->settings->minLength)->toBe(8);
});

it('returns a clone, not the live settings instance, on the merge path', function() {
    // Pro + per-group enabled + groups + policies — the resolver builds
    // a fresh clone via `clone $settings`. Pin so a future "skip the
    // clone if no overrides apply" optimisation doesn't accidentally
    // hand back the live instance.
    $group = GroupFactory::create();
    PolicyFactory::custom(['minLength' => 16], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $resolved = $this->resolver->resolveForUser($user);

    expect($resolved)->not->toBe($this->settings);
});

// =============================================================================
// Caching — current behavior codification
// =============================================================================

it('does not memoize the resolved policy across calls', function() {
    // Resolver has no per-user cache today — each call re-queries
    // `getPoliciesForGroupIds()`. Mutating a policy between two calls
    // should reflect on the second. Pin so a future cache-key bug
    // (e.g. "key includes user ID but not policy revision") catches
    // here.
    $group = GroupFactory::create();
    $policy = PolicyFactory::custom(['minLength' => 12], [$group]);

    $user = UserFactory::admin();
    $user->setGroups([$group]);

    $first = $this->resolver->resolveForUser($user);
    expect($first->minLength)->toBe(12);

    $policy->minLength = 18;
    PolicyFactory::save($policy, [$group]);

    $second = $this->resolver->resolveForUser($user);
    expect($second->minLength)->toBe(18);
});
