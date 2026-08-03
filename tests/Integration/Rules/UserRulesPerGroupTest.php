<?php
/**
 * Pest coverage for `UserRules::defineRules()` per-group resolution — the
 * systemic guarantee that a per-group policy override (complexity, minimum-
 * character-types, history depth) is ENFORCED at validate-time rather than
 * silently re-reading the laxer global `SettingsModel`.
 *
 * Each test builds a strict per-group policy, assigns the user to the group
 * in-memory, then materialises the rule set via `UserRules::defineRules($user)`
 * and runs every rule through Yii's `Validator::createValidator()` against the
 * user — the same path the User element's `defineRules` listener walks on save.
 * A password that satisfies the (lax) global policy but violates the (strict)
 * resolved per-group policy must be rejected; this catches the regression where
 * validators / pattern builders read the global model instead of the resolved
 * one.
 *
 * Edition + global settings mutate during tests — `beforeEach` snapshots and
 * `afterEach` restores. The DB transaction wrapper isolates policy/group rows,
 * and the fixtures this file creates are additionally torn down by hand: user
 * groups are project-config entities, so an explicit `deleteGroupById()` keeps
 * Craft's in-memory project config in step with the rolled-back `usergroups`
 * table, and the users are hard-deleted rather than left in the trash. Fixture
 * ownership belongs to the test, not to the transaction.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\elements\User;
use craft\models\UserGroup;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\rules\UserRules;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PasswordHistoryFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use yii\validators\Validator;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Creates a user group and registers it for teardown in `afterEach`.
 */
function trackedGroup(object $ctx): UserGroup
{
    $group = GroupFactory::create();
    $ctx->createdGroups[] = $group;

    return $group;
}

/**
 * Creates a non-admin user and registers it for teardown in `afterEach`.
 */
function trackedUser(object $ctx): User
{
    $user = UserFactory::nonAdmin();
    $ctx->createdUsers[] = $user;

    return $user;
}

/**
 * Runs every rule produced by `UserRules::defineRules($user)` against the
 * user's `newPassword`, returning the accumulated attribute errors. Mirrors
 * Yii's `Model::validate()` loop: each rule config becomes a Validator and
 * validates the named attributes on the model.
 */
function runUserPasswordRules(User $user, string $password): array
{
    $user->newPassword = $password;
    $user->clearErrors('newPassword');

    foreach (UserRules::defineRules($user) as $rule) {
        $attributes = (array)array_shift($rule);
        $type = array_shift($rule);

        $validator = Validator::createValidator($type, $user, $attributes, $rule);
        $validator->validateAttributes($user, ['newPassword']);
    }

    return $user->getErrors('newPassword');
}

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->createdGroups = [];
    $this->createdUsers = [];

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnablePerGroup = $this->settings->enablePerGroupPolicies;
    $this->originalMinLength = $this->settings->minLength;
    $this->originalComplexityMode = $this->settings->complexityMode;
    $this->originalMinTypes = $this->settings->minimumCharacterTypes;
    $this->originalHistoryCount = $this->settings->passwordHistoryCount;
    $this->originalCases = $this->settings->cases;
    $this->originalNumbers = $this->settings->numbers;
    $this->originalSymbols = $this->settings->symbols;

    // Per-group policies are Pro + opt-in.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->enablePerGroupPolicies = true;
});

afterEach(function() {
    // Users first — `usergroups_users` rows reference both sides, and a
    // hard delete takes the paired password-history rows with it.
    foreach ($this->createdUsers as $user) {
        Craft::$app->getElements()->deleteElement($user, true);
    }

    // Groups are project-config entities: `saveGroup()` routes through
    // `ProjectConfig::set()`, so rolling back the transaction restores the
    // `usergroups` table but leaves the group in the process's in-memory
    // project config. Deleting explicitly removes both.
    foreach ($this->createdGroups as $group) {
        Craft::$app->getUserGroups()->deleteGroupById($group->id);
    }

    $this->createdUsers = [];
    $this->createdGroups = [];

    $this->plugin->edition = $this->originalEdition;
    $this->settings->enablePerGroupPolicies = $this->originalEnablePerGroup;
    $this->settings->minLength = $this->originalMinLength;
    $this->settings->complexityMode = $this->originalComplexityMode;
    $this->settings->minimumCharacterTypes = $this->originalMinTypes;
    $this->settings->passwordHistoryCount = $this->originalHistoryCount;
    $this->settings->cases = $this->originalCases;
    $this->settings->numbers = $this->originalNumbers;
    $this->settings->symbols = $this->originalSymbols;
});

// =============================================================================
// Complexity (individual toggles) — per-group override enforced
// =============================================================================

it('enforces a per-group complexity override the global policy does not require', function() {
    // Global requires nothing beyond length; the per-group policy requires
    // numbers. A digit-less password passes global but must fail the resolved
    // per-group pattern — proving generatePattern() reads the resolved model.
    $this->settings->minLength = 4;
    $this->settings->cases = false;
    $this->settings->numbers = false;
    $this->settings->symbols = false;

    $group = trackedGroup($this);
    PolicyFactory::custom([
        'complexityMode' => 'individual',
        'cases' => false,
        'numbers' => true,
        'symbols' => false,
    ], [$group]);

    $user = trackedUser($this);
    $user->setGroups([$group]);

    expect(runUserPasswordRules($user, 'abcdefgh'))->not->toBeEmpty();

    // A digit satisfies the resolved requirement.
    $user2 = trackedUser($this);
    $user2->setGroups([$group]);
    expect(runUserPasswordRules($user2, 'abcdefg1'))->toBeEmpty();
});

// =============================================================================
// Minimum character types — per-group override enforced
// =============================================================================

it('enforces a per-group minimum-character-types override', function() {
    // Global is in "minimum" mode requiring 1 type; per-group requires 3.
    // A 2-class password passes global but must fail the resolved policy.
    $this->settings->minLength = 4;
    $this->settings->complexityMode = 'minimum';
    $this->settings->minimumCharacterTypes = 1;

    $group = trackedGroup($this);
    PolicyFactory::custom([
        'complexityMode' => 'minimum',
        'minimumCharacterTypes' => 3,
    ], [$group]);

    $user = trackedUser($this);
    $user->setGroups([$group]);

    // Lowercase + digit = 2 of 4 < 3.
    expect(runUserPasswordRules($user, 'abcd1234'))->not->toBeEmpty();

    // Lowercase + uppercase + digit = 3 of 4.
    $user2 = trackedUser($this);
    $user2->setGroups([$group]);
    expect(runUserPasswordRules($user2, 'Abcd1234'))->toBeEmpty();
});

// =============================================================================
// History depth — per-group override enforced
// =============================================================================

it('enforces a per-group history-depth override beyond the global window', function() {
    // Global window is 1 (only the newest entry is protected); the per-group
    // policy widens it to 5. Re-using the 3rd-newest entry must be rejected —
    // proving the resolved count threads into both the rule gate and the
    // service reuse check.
    $this->settings->minLength = 4;
    $this->settings->passwordHistoryCount = 1;

    $group = trackedGroup($this);
    PolicyFactory::custom(['passwordHistoryCount' => 5], [$group]);

    $user = trackedUser($this);
    $user->setGroups([$group]);

    PasswordHistoryFactory::seedFor($user, [
        'Old1!Pass',
        'Old2!Pass',
        'Old3!Pass',
        'Old4!Pass',
        'Old5!Pass',
    ], 5);

    $errors = runUserPasswordRules($user, 'Old3!Pass');

    expect($errors)->not->toBeEmpty()
        ->and(implode(' ', $errors))->toContain('used recently');
});
