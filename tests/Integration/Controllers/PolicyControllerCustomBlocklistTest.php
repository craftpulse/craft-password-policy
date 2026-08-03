<?php
/**
 * Pest coverage for `PolicyController::actionSave()`'s per-policy custom
 * blocklist payload (G6).
 *
 * Three contracts pinned here:
 *
 *  - **Enterprise write path.** A POST with `customBlocklist[<rowId>][word]`
 *    keys lands rows in `passwordpolicy_blocklist` with the right policyId
 *    and `source = 'custom'`.
 *  - **Diff-on-save.** Numeric rowIds whose word matches the stored value
 *    are kept, non-numeric keys are inserted, missing existing IDs are
 *    deleted. Single transaction wraps the policy save + the delta.
 *  - **Edition strip.** On Pro/Lite the controller unconditionally
 *    `unset()`s the payload before the diff runs; even crafted POSTs
 *    can't survive on a sub-edition install. The policy itself still
 *    saves.
 *
 * Tests run the action through `runAction()` so `beforeAction()` fires the
 * usual permission + admin-changes gates in the right order.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\PolicyController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\BlocklistFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalEdition = $this->plugin->edition;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);

    $this->plugin->getBlocklist()->clearCache();
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    $this->plugin->getBlocklist()->clearCache();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs `PolicyController::actionSave()` through `runAction()` so the
 * `requirePostRequest` / `_requireSettingsPermission` / `_requireAdminChanges`
 * / `_requireProEdition` gates fire in the right order.
 */
function runPolicySave(): mixed
{
    $controller = new PolicyController('policy', PasswordPolicy::$plugin);

    return $controller->runAction('save');
}

/**
 * Counts per-policy custom blocklist rows for a given policy id.
 */
function countPerPolicyRows(int $policyId): int
{
    return (int)(new Query())
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['source' => 'custom', 'policyId' => $policyId])
        ->count();
}

// =============================================================================
// Enterprise write path — happy paths
// =============================================================================

it('writes per-policy custom blocklist rows on Enterprise save', function() {
    $policy = PolicyFactory::custom(['handle' => 'g6E' . bin2hex(random_bytes(2))]);

    $this->request->stubBodyParams = [
        'policyId' => $policy->id,
        'name' => $policy->name,
        'handle' => $policy->handle,
        'preset' => '',
        'settings' => [],
        'groupIds' => [],
        'customBlocklist' => [
            'new1' => ['word' => 'AcmeCustomerName'],
            'new2' => ['word' => 'projectAtlas'],
        ],
    ];

    runPolicySave();

    $rows = (new Query())
        ->select(['word', 'policyId', 'source'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['policyId' => $policy->id])
        ->orderBy(['word' => SORT_ASC])
        ->all();

    expect($rows)->toHaveCount(2)
        ->and($rows[0]['word'])->toBe('acmecustomername') // lowercased
        ->and($rows[0]['source'])->toBe('custom')
        ->and((int)$rows[0]['policyId'])->toBe((int)$policy->id)
        ->and($rows[1]['word'])->toBe('projectatlas');
});

it('keeps existing rows whose word matches the stored value (numeric rowId)', function() {
    $policy = PolicyFactory::custom();

    BlocklistFactory::customWord('keepme', $policy->id);
    $existingRow = (new Query())
        ->select(['id', 'word'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['word' => 'keepme', 'policyId' => $policy->id])
        ->one();

    $this->request->stubBodyParams = [
        'policyId' => $policy->id,
        'name' => $policy->name,
        'handle' => $policy->handle,
        'preset' => '',
        'settings' => [],
        'groupIds' => [],
        'customBlocklist' => [
            // Numeric rowId matching a stored row → kept (no insert).
            (int)$existingRow['id'] => ['word' => 'keepme'],
        ],
    ];

    runPolicySave();

    // Same id still present — no delete-then-reinsert churn.
    $row = (new Query())
        ->select(['id', 'word'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['word' => 'keepme', 'policyId' => $policy->id])
        ->one();

    expect((int)$row['id'])->toBe((int)$existingRow['id']);
});

it('deletes rows omitted from the payload', function() {
    $policy = PolicyFactory::custom();

    BlocklistFactory::customWord('keepme', $policy->id);
    BlocklistFactory::customWord('removeme', $policy->id);

    $keepId = (int)(new Query())
        ->select(['id'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['word' => 'keepme', 'policyId' => $policy->id])
        ->scalar();

    $this->request->stubBodyParams = [
        'policyId' => $policy->id,
        'name' => $policy->name,
        'handle' => $policy->handle,
        'preset' => '',
        'settings' => [],
        'groupIds' => [],
        'customBlocklist' => [
            $keepId => ['word' => 'keepme'],
        ],
    ];

    runPolicySave();

    $words = (new Query())
        ->select(['word'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['policyId' => $policy->id])
        ->column();

    expect($words)->toBe(['keepme']);
});

it('inserts new rows from non-numeric (new1, new2) keys', function() {
    $policy = PolicyFactory::custom();
    BlocklistFactory::customWord('original', $policy->id);

    $existingId = (int)(new Query())
        ->select(['id'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['word' => 'original', 'policyId' => $policy->id])
        ->scalar();

    $this->request->stubBodyParams = [
        'policyId' => $policy->id,
        'name' => $policy->name,
        'handle' => $policy->handle,
        'preset' => '',
        'settings' => [],
        'groupIds' => [],
        'customBlocklist' => [
            $existingId => ['word' => 'original'],
            'new1' => ['word' => 'inserted'],
        ],
    ];

    runPolicySave();

    $words = (new Query())
        ->select(['word'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['policyId' => $policy->id])
        ->orderBy(['word' => SORT_ASC])
        ->column();

    expect($words)->toBe(['inserted', 'original']);
});

it('skips empty word rows in the payload', function() {
    $policy = PolicyFactory::custom();

    $this->request->stubBodyParams = [
        'policyId' => $policy->id,
        'name' => $policy->name,
        'handle' => $policy->handle,
        'preset' => '',
        'settings' => [],
        'groupIds' => [],
        'customBlocklist' => [
            'new1' => ['word' => ''],
            'new2' => ['word' => '   '],
            'new3' => ['word' => 'realword'],
        ],
    ];

    runPolicySave();

    $words = (new Query())
        ->select(['word'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['policyId' => $policy->id])
        ->column();

    expect($words)->toBe(['realword']);
});

// =============================================================================
// Edition strip — Pro/Lite silently drop the payload
// =============================================================================

it('silently strips customBlocklist payload on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $policy = PolicyFactory::custom();

    $this->request->stubBodyParams = [
        'policyId' => $policy->id,
        'name' => $policy->name,
        'handle' => $policy->handle,
        'preset' => '',
        'settings' => [],
        'groupIds' => [],
        'customBlocklist' => [
            'new1' => ['word' => 'craftedinjection'],
        ],
    ];

    runPolicySave();

    expect(countPerPolicyRows((int)$policy->id))->toBe(0);
});

it('does not strip global custom blocklist rows when policy save runs on Pro', function() {
    // Pro continues to support global custom blocklist via the dedicated
    // BlocklistController. Pin that the per-policy strip doesn't reach
    // into the global table by mistake.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    BlocklistFactory::customWord('globalrow', null);
    $policy = PolicyFactory::custom();

    $this->request->stubBodyParams = [
        'policyId' => $policy->id,
        'name' => $policy->name,
        'handle' => $policy->handle,
        'preset' => '',
        'settings' => [],
        'groupIds' => [],
        'customBlocklist' => [
            'new1' => ['word' => 'craftedinjection'],
        ],
    ];

    runPolicySave();

    $globalCount = (int)(new Query())
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['source' => 'custom', 'policyId' => null])
        ->count();

    expect($globalCount)->toBe(1);
});
