<?php
/**
 * Pest coverage for `PolicyElement` + `PolicyQuery` — the Step 6
 * element-ification surface for `passwordpolicy_policies`. Verifies
 * the element-record pairing, the model→element→record translation
 * via `PolicyService::savePolicy()`, status resolution, custom
 * query params (handle, preset, groupId), the canonical `enabled`
 * status, element-type registration, and FK count post-migration.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\elements\PolicyElement;
use craftpulse\passwordpolicy\enums\PolicyPreset;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\PolicyRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;

// =============================================================================
// Setup — Pro edition, wipe rows so per-test queries are deterministic
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_policy_groups}}')
        ->execute();
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_policies}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Element-record pairing — element id IS record id IS craft_elements.id
// =============================================================================

it('saves a policy via the service and re-queries via the element pipeline', function() {
    $policy = PolicyFactory::nist();

    $element = PolicyElement::find()->id($policy->id)->one();

    expect($element)->toBeInstanceOf(PolicyElement::class);
    expect((int)$element->id)->toBe($policy->id);
    expect($element->handle)->toBe($policy->handle);
    expect($element->preset)->toBe(PolicyPreset::NIST_800_63B->value);
});

it('persists a paired PolicyRecord with the same id as the element', function() {
    $policy = PolicyFactory::owasp();

    /** @var PolicyRecord|null $record */
    $record = PolicyRecord::findOne($policy->id);

    expect($record)->not->toBeNull();
    expect((int)$record->id)->toBe($policy->id);
    expect($record->handle)->toBe($policy->handle);
    expect($record->preset)->toBe(PolicyPreset::OWASP_ASVS->value);
});

it('pairs element id with craft_elements.id via the FK', function() {
    $policy = PolicyFactory::nist();

    $elementRow = (new Query())
        ->from('{{%elements}}')
        ->where(['id' => $policy->id])
        ->one();

    expect($elementRow)->not->toBeFalse();
    expect((int)$elementRow['id'])->toBe($policy->id);
    expect($elementRow['type'])->toBe(PolicyElement::class);
});

// =============================================================================
// Status — every saved policy is 'enabled' in 5.2.0
// =============================================================================

it('returns enabled status for every saved policy', function() {
    $policy = PolicyFactory::nist();

    $element = PolicyElement::find()->id($policy->id)->one();

    expect($element->getStatus())->toBe('enabled');
});

it('exposes both enabled + disabled in the statuses() map', function() {
    $statuses = PolicyElement::statuses();

    expect($statuses)->toHaveKey('enabled');
    expect($statuses)->toHaveKey('disabled');
    expect($statuses['enabled']['color'])->toBe('green');
});

// =============================================================================
// Custom query params — handle, preset, groupId
// =============================================================================

it('filters by handle', function() {
    PolicyFactory::custom(['handle' => 'devTeam']);
    PolicyFactory::custom(['handle' => 'adminTeam']);

    $matches = PolicyElement::find()->handle('devTeam')->all();

    expect($matches)->toHaveCount(1);
    expect($matches[0]->handle)->toBe('devTeam');
});

it('filters by preset', function() {
    PolicyFactory::nist();
    PolicyFactory::owasp();

    $nist = PolicyElement::find()->preset(PolicyPreset::NIST_800_63B->value)->all();
    $owasp = PolicyElement::find()->preset(PolicyPreset::OWASP_ASVS->value)->all();

    expect($nist)->toHaveCount(1);
    expect($owasp)->toHaveCount(1);
    expect($nist[0]->preset)->toBe(PolicyPreset::NIST_800_63B->value);
});

it('filters by groupId via the junction', function() {
    $devGroup = GroupFactory::create();
    $otherGroup = GroupFactory::create();

    $devPolicy = PolicyFactory::nist([$devGroup]);
    PolicyFactory::owasp([$otherGroup]);

    $matchingDev = PolicyElement::find()->groupId($devGroup->id)->all();

    expect($matchingDev)->toHaveCount(1);
    expect((int)$matchingDev[0]->id)->toBe($devPolicy->id);
});

// =============================================================================
// Sources — the index lands on 'All policies' with sortOrder ascending
// =============================================================================

it('exposes a single All source', function() {
    $reflection = new \ReflectionMethod(PolicyElement::class, 'defineSources');
    $reflection->setAccessible(true);
    $sources = $reflection->invoke(null, null);

    expect($sources)->toHaveCount(1);
    expect($sources[0]['key'])->toBe('*');
});

// =============================================================================
// Element-type registration — Craft sees the class via the registry event
// =============================================================================

it('registers PolicyElement as a Craft element type', function() {
    $types = Craft::$app->getElements()->getAllElementTypes();

    expect(in_array(PolicyElement::class, $types, true))->toBeTrue();
});

// =============================================================================
// FK count regression — Step 6 migration leaves exactly the canonical set,
// no duplicates from any of the prior element conversions
// =============================================================================

it('leaves exactly one FK on passwordpolicy_policies after the migration', function() {
    $db = Craft::$app->getDb();
    $currentDatabase = $db->createCommand('SELECT DATABASE()')->queryScalar();

    $fkCount = (new Query())
        ->from('INFORMATION_SCHEMA.KEY_COLUMN_USAGE')
        ->where([
            'TABLE_SCHEMA' => $currentDatabase,
            'TABLE_NAME' => $db->getSchema()->getRawTableName('{{%passwordpolicy_policies}}'),
        ])
        ->andWhere(['is not', 'REFERENCED_TABLE_NAME', null])
        ->count();

    expect((int)$fkCount)->toBe(1);
});

it('leaves two FKs on the policy_groups junction after the migration', function() {
    $db = Craft::$app->getDb();
    $currentDatabase = $db->createCommand('SELECT DATABASE()')->queryScalar();

    $fkCount = (new Query())
        ->from('INFORMATION_SCHEMA.KEY_COLUMN_USAGE')
        ->where([
            'TABLE_SCHEMA' => $currentDatabase,
            'TABLE_NAME' => $db->getSchema()->getRawTableName('{{%passwordpolicy_policy_groups}}'),
        ])
        ->andWhere(['is not', 'REFERENCED_TABLE_NAME', null])
        ->count();

    expect((int)$fkCount)->toBe(2);
});

// =============================================================================
// Authorization — canView / canSave / canDelete admin or pp:manage-settings
// =============================================================================

it('allows admin view + save + delete', function() {
    $admin = \craftpulse\passwordpolicy\tests\Support\Factories\UserFactory::admin();

    $element = new PolicyElement();

    expect($element->canView($admin))->toBeTrue();
    expect($element->canSave($admin))->toBeTrue();
    expect($element->canDelete($admin))->toBeTrue();
});

// =============================================================================
// fromModel / fromElement translation
// =============================================================================

it('translates a PolicyModel onto a PolicyElement', function() {
    $devGroup = GroupFactory::create();
    $model = new PolicyModel();
    $model->name = 'Test Translation';
    $model->handle = 'testTranslation';
    $model->preset = PolicyPreset::NIST_800_63B->value;
    $model->setSettingsFromArray(['minLength' => 14]);

    $element = PolicyElement::fromModel($model, [$devGroup->id]);

    expect($element)->toBeInstanceOf(PolicyElement::class);
    expect($element->name)->toBe('Test Translation');
    expect($element->handle)->toBe('testTranslation');
    expect($element->preset)->toBe(PolicyPreset::NIST_800_63B->value);
    expect($element->groupIds)->toBe([$devGroup->id]);
});

it('translates a saved PolicyElement back into a PolicyModel', function() {
    $policy = PolicyFactory::strict();

    $element = PolicyElement::find()->id($policy->id)->one();
    $rehydrated = PolicyModel::fromElement($element);

    expect($rehydrated)->toBeInstanceOf(PolicyModel::class);
    expect($rehydrated->id)->toBe($policy->id);
    expect($rehydrated->handle)->toBe($policy->handle);
    expect($rehydrated->preset)->toBe(PolicyPreset::STRICT_ENTERPRISE->value);
});
