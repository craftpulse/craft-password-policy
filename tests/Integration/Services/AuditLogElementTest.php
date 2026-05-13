<?php
/**
 * Pest coverage for `AuditLogElement` + `AuditLogQuery` — the Step 5
 * element-ification surface. Verifies the element-record pairing,
 * status filtering by `outcome`, custom query params, the append-only
 * + admin-only-delete contract, and that the chain bytes survive the
 * element round-trip (a row written via the service can be re-read
 * via the element and produces the same canonical payload bytes the
 * verifier consumes).
 *
 * The audit-log feature flag (`enableAuditLog`) is flipped on at setup
 * since the playground default is `false`.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\AuditLogRecord;
use craftpulse\passwordpolicy\services\AuditLogService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup — Pro edition, audit log enabled, wipe rows so per-test queries are
// deterministic
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
// Element-record pairing — element id IS record id IS craft_elements.id
// =============================================================================

it('writes via the service and re-queries via the element pipeline', function() {
    $rowId = $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
        outcome: 'success',
        source: 'cli',
    );

    expect($rowId)->toBeInt();

    $element = AuditLogElement::find()->id($rowId)->one();

    expect($element)->toBeInstanceOf(AuditLogElement::class);
    expect((int)$element->id)->toBe($rowId);
    expect($element->event)->toBe('password_changed');
    expect($element->outcome)->toBe('success');
    expect($element->source)->toBe('cli');
    expect($element->rowHash)->toMatch('/^[0-9a-f]{64}$/');
    expect($element->previousHash)->toBe(str_repeat('0', 64));
});

it('persists a paired AuditLogRecord with the same id as the element', function() {
    $rowId = $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    /** @var AuditLogRecord|null $record */
    $record = AuditLogRecord::findOne($rowId);

    expect($record)->not->toBeNull();
    expect((int)$record->id)->toBe($rowId);
    expect($record->event)->toBe('password_changed');
    expect($record->rowHash)->toMatch('/^[0-9a-f]{64}$/');
});

// =============================================================================
// Chain invariant — bytes match between the writer and the element re-read
// =============================================================================

it('preserves chain bytes across the element round-trip', function() {
    // Write via the service (element pipeline)
    $rowId = $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
        outcome: 'success',
        source: 'cli',
    );

    // Re-read the raw row (the verifier path) AND the element (the
    // CP-index path). Both must reflect the same persisted chain bytes.
    $rawRow = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $rowId])
        ->one();

    $element = AuditLogElement::find()->id($rowId)->one();

    expect($element->rowHash)->toBe($rawRow['rowHash']);
    expect($element->previousHash)->toBe($rawRow['previousHash']);

    // Recompute canonicalize → sha256 from the raw row and verify the
    // element's stored rowHash matches. Pins L1 (canonical bytes
    // unchanged across the refactor).
    $canonical = AuditLogService::canonicalize([
        'changedByUserId' => $rawRow['changedByUserId'] !== null
            ? (int)$rawRow['changedByUserId']
            : null,
        'dateCreated' => (new \DateTime($rawRow['dateCreated'], new \DateTimeZone('UTC')))
            ->format(AuditLogService::CANONICAL_DATE_FORMAT),
        'details' => null,
        'event' => 'password_changed',
        'ipHash' => $rawRow['ipHash'],
        'outcome' => 'success',
        'source' => 'cli',
        'uid' => $rawRow['uid'],
        'userId' => null,
        'userIdentifier' => null,
    ]);

    $expectedHash = hash('sha256', $canonical . $rawRow['previousHash']);

    expect($element->rowHash)->toBe($expectedHash);
});

// =============================================================================
// Status filtering — element-index `outcome:success` / `outcome:failure`
// =============================================================================

it('filters by element-index status (success / failure)', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
        outcome: 'success',
    );
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
        outcome: 'failure',
    );
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'account_locked',
        outcome: 'success',
    );

    $success = AuditLogElement::find()->status('success')->all();
    $failure = AuditLogElement::find()->status('failure')->all();
    $all = AuditLogElement::find()->status(null)->all();

    expect($success)->toHaveCount(2);
    expect($failure)->toHaveCount(1);
    expect($all)->toHaveCount(3);
});

// =============================================================================
// Custom query params
// =============================================================================

it('filters by event machine-key', function() {
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'account_locked');

    $changed = AuditLogElement::find()->event('password_changed')->status(null)->all();
    $locked = AuditLogElement::find()->event('account_locked')->status(null)->all();

    expect($changed)->toHaveCount(1);
    expect($locked)->toHaveCount(1);
    expect($changed[0]->event)->toBe('password_changed');
    expect($locked[0]->event)->toBe('account_locked');
});

it('filters by outcome via the dedicated setter', function() {
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed', outcome: 'success');
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed', outcome: 'failure');

    $failures = AuditLogElement::find()->outcome('failure')->status(null)->all();

    expect($failures)->toHaveCount(1);
    expect($failures[0]->outcome)->toBe('failure');
});

it('filters by source context', function() {
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed', source: 'admin');
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed', source: 'cli');

    $admin = AuditLogElement::find()->source('admin')->status(null)->all();

    expect($admin)->toHaveCount(1);
    expect($admin[0]->source)->toBe('admin');
});

it('filters by forwardedAt = false (unforwarded rows)', function() {
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');

    // Mark one as forwarded
    $rows = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_audit_log}}',
            ['forwardedAt' => '2026-01-01 00:00:00'],
            ['id' => (int)$rows[0]['id']],
        )
        ->execute();

    $unforwarded = AuditLogElement::find()->forwardedAt(false)->status(null)->all();
    $forwarded = AuditLogElement::find()->forwardedAt(true)->status(null)->all();

    expect($unforwarded)->toHaveCount(1);
    expect($forwarded)->toHaveCount(1);
});

// =============================================================================
// userId nullability — audit row outlives the user
// =============================================================================

it('accepts a null userId for system-level events', function() {
    $rowId = $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'policy_changed',
    );

    expect($rowId)->toBeInt();

    $element = AuditLogElement::find()->id($rowId)->status(null)->one();

    expect($element)->not->toBeNull();
    expect($element->userId)->toBeNull();
});

it('hydrates auditUserId for user-scoped events', function() {
    $user = UserFactory::admin();

    $rowId = $this->plugin->getAuditLog()->logEvent(
        userId: $user->id,
        event: 'password_changed',
    );

    $element = AuditLogElement::find()
        ->auditUserId($user->id)
        ->status(null)
        ->one();

    expect($element)->not->toBeNull();
    expect((int)$element->id)->toBe($rowId);
    expect($element->userId)->toBe($user->id);
});

// =============================================================================
// Authorization — canSave always false, canDelete admin-only
// =============================================================================

it('refuses CP save attempts (append-only contract)', function() {
    $admin = UserFactory::admin();

    $element = new AuditLogElement();
    $element->event = 'password_changed';
    $element->outcome = 'success';

    expect($element->canSave($admin))->toBeFalse();
});

it('allows admin-only delete', function() {
    $admin = UserFactory::admin();

    $element = new AuditLogElement();
    $element->event = 'password_changed';

    expect($element->canDelete($admin))->toBeTrue();
});

// =============================================================================
// Element-type registration — Craft sees the class via the registry event
// =============================================================================

it('registers AuditLogElement as a Craft element type', function() {
    $types = Craft::$app->getElements()->getAllElementTypes();

    expect(in_array(AuditLogElement::class, $types, true))->toBeTrue();
});
