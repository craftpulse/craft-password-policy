<?php
/**
 * Pest coverage for `AuditLogService`'s SHA-256 forward chain — the
 * Phase G compliance foundation. Pins the contract a verifier (G2) can
 * recompute against:
 *
 *  - Every row's `rowHash` is `sha256(canonicalize(payload) . previousHash)`.
 *  - Row N's `previousHash` is row N-1's `rowHash` (in id order).
 *  - The genesis row's `previousHash` is sixty-four zero hex chars.
 *  - Capture is universal — Lite installs write the chain too. Edition
 *    gates the dashboard / verifier UI / forwarder / export, never the
 *    underlying writes (memory rule `project_audit_capture_principle.md`).
 *
 * Tests run on Pro edition by default, but flip to Lite once to lock the
 * universal-capture invariant. The audit-log feature flag (`enableAuditLog`)
 * is enabled at setup since the playground default is `false`.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;

// =============================================================================
// Setup — flip enableAuditLog on for every test in this file, restore after
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->enableAuditLog = true;

    // Wipe any audit rows seeded by previous tests so the genesis-row
    // assertion below is deterministic. The standard transaction
    // wrapper rolls each test back, but seeded rows from prior session
    // runs (or manual playground clicks) survive.
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
});

// =============================================================================
// Genesis row — first row anchors to the all-zeros previousHash sentinel
// =============================================================================

it('writes the genesis row with previousHash = sixty-four zeros', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    /** @var array<string, mixed>|null $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->one();

    expect($row)->not->toBeNull();
    expect($row['previousHash'])->toBe(str_repeat('0', 64));
    expect($row['rowHash'])->toMatch('/^[0-9a-f]{64}$/');
    expect($row['rowHash'])->not->toBe(str_repeat('0', 64));
});

// =============================================================================
// Hash matches a hand-rolled reference computation
// =============================================================================

it('writes a rowHash that matches the canonicalize+sha256 reference', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
        outcome: 'success',
        source: 'cli',
    );

    /** @var array<string, mixed>|null $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->one();

    expect($row)->not->toBeNull();

    $expectedPayload = AuditLogService::canonicalize([
        'changedByUserId' => $row['changedByUserId'],
        'dateCreated' => (new \DateTime($row['dateCreated'], new \DateTimeZone('UTC')))
            ->format('Y-m-d\TH:i:s\Z'),
        'details' => null,
        'event' => 'password_changed',
        'ipHash' => $row['ipHash'],
        'outcome' => 'success',
        'source' => 'cli',
        'uid' => $row['uid'],
        'userId' => null,
        'userIdentifier' => null,
    ]);

    $expectedHash = hash('sha256', $expectedPayload . str_repeat('0', 64));

    expect($row['rowHash'])->toBe($expectedHash);
    expect($row['previousHash'])->toBe(str_repeat('0', 64));
});

// =============================================================================
// Three-row chain — each row's previousHash matches the prior row's rowHash
// =============================================================================

it('chains rows via previousHash referencing the prior rowHash', function() {
    $service = $this->plugin->getAuditLog();

    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');

    /** @var array<int, array<string, mixed>> $rows */
    $rows = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    expect($rows)->toHaveCount(3);

    expect($rows[0]['previousHash'])->toBe(str_repeat('0', 64));
    expect($rows[1]['previousHash'])->toBe($rows[0]['rowHash']);
    expect($rows[2]['previousHash'])->toBe($rows[1]['rowHash']);

    // Every row's hash is itself a 64-char hex digest and unique
    foreach ($rows as $row) {
        expect($row['rowHash'])->toMatch('/^[0-9a-f]{64}$/');
    }

    expect($rows[0]['rowHash'])->not->toBe($rows[1]['rowHash']);
    expect($rows[1]['rowHash'])->not->toBe($rows[2]['rowHash']);
});

// =============================================================================
// Capture is universal — Lite edition writes the chain too
// =============================================================================

it('writes the chain on Lite edition (capture is universal)', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    /** @var array<string, mixed>|null $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'password_changed'])
        ->one();

    expect($row)->not->toBeNull();
    expect($row['rowHash'])->toMatch('/^[0-9a-f]{64}$/');
    expect($row['rowHash'])->not->toBe(str_repeat('0', 64));
});

// =============================================================================
// enableAuditLog feature flag still gates the write
// =============================================================================

it('skips the write when enableAuditLog is false', function() {
    $this->plugin->getSettings()->enableAuditLog = false;

    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
    );

    $exists = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'password_changed'])
        ->exists();

    expect($exists)->toBeFalse();
});
