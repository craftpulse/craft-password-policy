<?php
/**
 * Pest coverage for `PolicyService::savePolicy()` field-level diff
 * capture (Phase G — G4).
 *
 * Pins the `policy_changed` audit-event contract:
 *
 *  - On UPDATE, every changed field lands in `details.diff` shaped as
 *    `{field: {old: <value>, new: <value>}}`. Unchanged fields are
 *    omitted entirely.
 *  - INSERTs do not fire `policy_changed` — a brand-new policy has
 *    nothing to diff against. (A future `policy_created` event class
 *    is out of scope for G4.)
 *  - A no-op save (caller passes the identical model + identical group
 *    set) writes no audit row.
 *  - Boolean tri-state fields (`?bool`) round-trip `null` / `true` /
 *    `false` literally — no coercion.
 *  - Group assignments (`groupIds`) emit FULL old + new arrays when
 *    changed. Order is not semantic — both arrays are sorted before
 *    comparison.
 *  - The audit row's chain payload still canonicalises deterministically.
 *    The verifier's contract from G1/G2 is unaffected by the diff
 *    payload's nested shape.
 *
 * Maps to ISO 27002 A.5.37, SOC 2 CC8.1, NIS2 Article 21(2)(e)
 * change-management evidence.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;

// =============================================================================
// Setup — flip enableAuditLog on for every test, restore after, clear rows
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
});

// =============================================================================
// Helpers — fetch the latest `policy_changed` row + decode its details
// =============================================================================

/**
 * Returns the freshly-decoded details payload of the most recent
 * `policy_changed` audit row. Returns `null` if no row exists.
 *
 * MariaDB's `JSON` column type alphabetises top-level keys on read, so
 * round-tripped payloads come back with their key order normalised
 * (`new` before `old`). The chain hash is unaffected because
 * `AuditLogService::canonicalize()` recursively sorts before hashing
 * — both the writer's input and the DB's read-back canonicalise to
 * identical bytes.
 *
 * @return array<string, mixed>|null
 */
function ppLatestPolicyChangedDetails(): ?array
{
    /** @var array<string, mixed>|false $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'policy_changed'])
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->one();

    if (!is_array($row)) {
        return null;
    }

    $details = is_string($row['details'])
        ? json_decode($row['details'], true)
        : $row['details'];

    return is_array($details) ? $details : null;
}

// =============================================================================
// Field changes — diff records old + new, omits unchanged fields
// =============================================================================

it('records a diff entry when a settings field changes', function() {
    $policy = PolicyFactory::custom([
        'minLength' => 8,
        'cases' => true,
    ]);

    // Reload to detach from any cached groupIds resolution.
    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $reloaded->minLength = 12;

    $this->plugin->getPolicies()->savePolicy($reloaded);

    $details = ppLatestPolicyChangedDetails();

    expect($details)->not->toBeNull();
    expect($details)->toHaveKey('diff');
    expect($details['diff'])->toHaveKey('minLength');
    expect($details['diff']['minLength'])->toBe(['new' => 12, 'old' => 8]);

    // Unchanged fields must NOT appear.
    expect($details['diff'])->not->toHaveKey('cases');
    expect($details['diff'])->not->toHaveKey('handle');
    expect($details['diff'])->not->toHaveKey('name');

    // Non-diff identification keys land alongside the diff.
    expect($details)->toHaveKey('policyId');
    expect($details['policyId'])->toBe((int)$policy->id);
    expect($details)->toHaveKey('policyName');
    expect($details['policyName'])->toBe($reloaded->name);
});

it('writes no audit row when the save is a no-op', function() {
    $policy = PolicyFactory::custom(['minLength' => 10]);

    // Drop the seed-row that the initial INSERT does NOT fire (G4
    // skips inserts), then save the same policy with no changes.
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $this->plugin->getPolicies()->savePolicy($reloaded);

    $count = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'policy_changed'])
        ->count();

    expect((int)$count)->toBe(0);
});

it('does not fire policy_changed on the INSERT path', function() {
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    PolicyFactory::custom(['minLength' => 14]);

    $count = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'policy_changed'])
        ->count();

    expect((int)$count)->toBe(0);
});

// =============================================================================
// Top-level columns — name, handle, preset, sortOrder all surface in the diff
// =============================================================================

it('records top-level column changes (name, handle, preset, sortOrder)', function() {
    $policy = PolicyFactory::custom([
        'name' => 'Original Name',
        'handle' => 'originalHandle',
    ]);

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $reloaded->name = 'Renamed Policy';
    $reloaded->handle = 'renamedHandle';
    $reloaded->preset = 'nist_800_63b';
    $reloaded->sortOrder = 5;

    $this->plugin->getPolicies()->savePolicy($reloaded);

    $details = ppLatestPolicyChangedDetails();

    expect($details)->not->toBeNull();
    expect($details['diff']['name'])->toBe(['new' => 'Renamed Policy', 'old' => 'Original Name']);
    expect($details['diff']['handle'])->toBe(['new' => 'renamedHandle', 'old' => 'originalHandle']);
    expect($details['diff']['preset'])->toBe(['new' => 'nist_800_63b', 'old' => null]);
    expect($details['diff']['sortOrder'])->toBe(['new' => 5, 'old' => 0]);
});

// =============================================================================
// Boolean tri-state fields — null / true / false round-trip literally
// =============================================================================

it('captures the null → true transition for a tri-state setting', function() {
    $policy = PolicyFactory::custom([]);

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();
    expect($reloaded->cases)->toBeNull();

    $reloaded->cases = true;
    $this->plugin->getPolicies()->savePolicy($reloaded);

    $details = ppLatestPolicyChangedDetails();
    expect($details)->not->toBeNull();
    expect($details['diff'])->toHaveKey('cases');
    expect($details['diff']['cases'])->toBe(['new' => true, 'old' => null]);
});

it('captures the true → false transition for a tri-state setting', function() {
    $policy = PolicyFactory::custom(['cases' => true]);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $reloaded->cases = false;
    $this->plugin->getPolicies()->savePolicy($reloaded);

    $details = ppLatestPolicyChangedDetails();
    expect($details)->not->toBeNull();
    expect($details['diff']['cases'])->toBe(['new' => false, 'old' => true]);
});

it('captures the false → null transition for a tri-state setting', function() {
    $policy = PolicyFactory::custom(['cases' => false]);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $reloaded->cases = null;
    $this->plugin->getPolicies()->savePolicy($reloaded);

    $details = ppLatestPolicyChangedDetails();
    expect($details)->not->toBeNull();
    expect($details['diff']['cases'])->toBe(['new' => null, 'old' => false]);
});

// =============================================================================
// Group assignments — full arrays emitted, order-insensitive comparison
// =============================================================================

it('records groupIds changes as full old + new arrays', function() {
    $groupA = GroupFactory::editors();
    $groupB = GroupFactory::managers();
    $groupC = GroupFactory::create();

    $policy = PolicyFactory::custom([], [$groupA, $groupB]);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $newGroupIds = [(int)$groupB->id, (int)$groupC->id];

    $this->plugin->getPolicies()->savePolicy($reloaded, $newGroupIds);

    $details = ppLatestPolicyChangedDetails();
    expect($details)->not->toBeNull();
    expect($details['diff'])->toHaveKey('groupIds');

    $expectedOld = [(int)$groupA->id, (int)$groupB->id];
    $expectedNew = [(int)$groupB->id, (int)$groupC->id];
    sort($expectedOld, SORT_NUMERIC);
    sort($expectedNew, SORT_NUMERIC);

    expect($details['diff']['groupIds'])->toBe([
        'new' => $expectedNew,
        'old' => $expectedOld,
    ]);
});

it('does not diff groupIds when only the order changes', function() {
    $groupA = GroupFactory::editors();
    $groupB = GroupFactory::managers();

    $policy = PolicyFactory::custom([], [$groupA, $groupB]);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    // Save with the same set of groups but in a different order.
    // Group order isn't semantic — no diff entry should appear.
    $this->plugin->getPolicies()->savePolicy(
        $reloaded,
        [(int)$groupB->id, (int)$groupA->id],
    );

    $count = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'policy_changed'])
        ->count();

    expect((int)$count)->toBe(0);
});

// =============================================================================
// Chain integrity — diff payload doesn't break canonicalisation
// =============================================================================

it('canonicalises the diff payload deterministically', function() {
    $policy = PolicyFactory::custom(['minLength' => 8]);

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $reloaded->minLength = 12;
    $reloaded->cases = true;

    $this->plugin->getPolicies()->savePolicy($reloaded);

    $details = ppLatestPolicyChangedDetails();
    expect($details)->not->toBeNull();

    // Re-encoding the details payload through `canonicalize()` twice
    // produces identical output. That's the byte-stability contract
    // the chain verifier walks against.
    $first = AuditLogService::canonicalize($details);
    $second = AuditLogService::canonicalize($details);

    expect($first)->toBe($second);

    // The canonical form must be alphabetically ordered at every depth.
    // Spot-check the top-level key order: `diff`, `policyId`, `policyName`.
    $expectedPrefix = '{"diff":';
    expect(str_starts_with($first, $expectedPrefix))->toBeTrue();
});

it('writes a chain-walkable row when the diff is the only details payload', function() {
    $policy = PolicyFactory::custom(['minLength' => 8]);

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();

    $reloaded->minLength = 16;
    $this->plugin->getPolicies()->savePolicy($reloaded);

    /** @var array<string, mixed>|false $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'policy_changed'])
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->one();

    expect($row)->not->toBeNull();
    expect($row['rowHash'])->toMatch('/^[0-9a-f]{64}$/');
    expect($row['previousHash'])->toMatch('/^[0-9a-f]{64}$/');
    expect($row['rowHash'])->not->toBe($row['previousHash']);
});

// =============================================================================
// Allowlist enforcement — non-allowlisted keys stripped, even on policy_changed
// =============================================================================

it('strips a non-allowlisted key from policy_changed details', function() {
    // Direct logEvent call to assert the registry filters the
    // `policy_changed` event class the same way it filters every other
    // event — defense-in-depth coverage on top of the codebase-grep
    // fixture in `AuditAllowlistRegistryTest`.
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'policy_changed',
        details: [
            'diff' => ['minLength' => ['old' => 8, 'new' => 12]],
            'plaintext' => 'should-never-be-stored',
            'policyId' => 99,
            'policyName' => 'Filter test',
        ],
    );

    $details = ppLatestPolicyChangedDetails();

    expect($details)->not->toBeNull();
    expect($details)->toHaveKey('diff');
    expect($details)->toHaveKey('policyId');
    expect($details)->toHaveKey('policyName');
    expect($details)->not->toHaveKey('plaintext');
});
