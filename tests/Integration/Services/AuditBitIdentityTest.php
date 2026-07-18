<?php
/**
 * Bit-identity regression pin for the audit hash chain after the 5.2.0
 * migration onto the shared Audit Kit engine (`Canonicalizer` +
 * `ChainWriter`).
 *
 * ⚠️ THE UNBREAKABLE CONSTRAINT: live 5.1.x installs carry production hash
 * chains written by PP's own (pre-kit) canonicalisation code. The kit engine
 * MUST reproduce those bytes exactly — same canonical key set, same
 * canonicalisation bytes, same genesis sentinel, same
 * `rowHash = sha256(canonicalize(payload) . previousHash)` computation.
 *
 * The golden vector below was computed from the CURRENT (pre-refactor) code
 * path — `AuditLogService::canonicalize()` over the representative 9-key audit
 * payload, hashed against the genesis sentinel — and hard-pinned here. If the
 * kit ever drifts (a JSON flag flips across a PHP minor, someone "tidies" the
 * recursive sort, a key is added/removed/reordered), this test fails LOUD
 * before a single production chain silently breaks in the wild.
 *
 * This is the durable companion to the live-chain gate: the playground's
 * pre-refactor `passwordpolicy_audit_log` table (460 production-shaped rows)
 * still passes `password-policy/audit/verify` post-refactor because the kit
 * recomputes identical bytes — the same property this vector pins in code.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\auditkit\engine\Canonicalizer;
use craftpulse\passwordpolicy\services\AuditLogService;

// =============================================================================
// The golden vector — captured from the pre-kit code path, frozen forever
// =============================================================================

/**
 * The representative 9-key canonical audit payload, in the exact shape
 * `AuditLogService::logEvent()` hashes (immutable columns only; mutable FK
 * ints + geo excluded).
 *
 * @return array<string, mixed>
 */
function goldenAuditPayload(): array
{
    return [
        'changedByIdentifier' => 'hmac-of-actor-email',
        'dateCreated' => '2026-05-07T08:12:01Z',
        'details' => ['violationType' => 'expired', 'reason' => 'Force reset'],
        'event' => 'force_reset',
        'ipHash' => 'abc123',
        'outcome' => 'success',
        'source' => 'admin',
        'uid' => '5b3f-uid',
        'userIdentifier' => 'hmac-of-email',
    ];
}

const GOLDEN_CANONICAL = '{"changedByIdentifier":"hmac-of-actor-email",'
    . '"dateCreated":"2026-05-07T08:12:01Z",'
    . '"details":{"reason":"Force reset","violationType":"expired"},'
    . '"event":"force_reset",'
    . '"ipHash":"abc123",'
    . '"outcome":"success",'
    . '"source":"admin",'
    . '"uid":"5b3f-uid",'
    . '"userIdentifier":"hmac-of-email"}';

// Computed from the CURRENT code before the refactor:
//   hash('sha256', GOLDEN_CANONICAL . str_repeat('0', 64))
const GOLDEN_ROWHASH = '807c117aa29bd2913a8be870f3bf52b0dc5f0a6c005689064810ffdfab63f6f1';

// =============================================================================
// Canonical bytes — the kit reproduces PP's exact canonicalisation output
// =============================================================================

it('reproduces the golden canonical bytes through the kit Canonicalizer', function() {
    expect(AuditLogService::canonicalize(goldenAuditPayload()))->toBe(GOLDEN_CANONICAL);
    expect(Canonicalizer::canonicalize(goldenAuditPayload()))->toBe(GOLDEN_CANONICAL);
});

// =============================================================================
// Genesis sentinel + date format — the constants PP's readers import stay put
// =============================================================================

it('pins the genesis sentinel and canonical date format to the kit values', function() {
    expect(AuditLogService::GENESIS_PREVIOUS_HASH)->toBe(str_repeat('0', 64));
    expect(AuditLogService::GENESIS_PREVIOUS_HASH)->toBe(Canonicalizer::GENESIS_PREVIOUS_HASH);
    expect(AuditLogService::CANONICAL_DATE_FORMAT)->toBe('Y-m-d\TH:i:s\Z');
    expect(AuditLogService::CANONICAL_DATE_FORMAT)->toBe(Canonicalizer::CANONICAL_DATE_FORMAT);
});

// =============================================================================
// rowHash — the exact byte the writer + verifier produce for a genesis row
// =============================================================================

it('computes the golden rowHash for a genesis row', function() {
    $rowHash = hash(
        'sha256',
        AuditLogService::canonicalize(goldenAuditPayload()) . AuditLogService::GENESIS_PREVIOUS_HASH,
    );

    expect($rowHash)->toBe(GOLDEN_ROWHASH);
});

// =============================================================================
// End-to-end write — a real logEvent() row self-verifies against the kit
// recompute, proving the write path bytes match the verifier's
// =============================================================================

it('writes a real row whose stored rowHash matches the kit recompute', function() {
    $plugin = \craftpulse\passwordpolicy\PasswordPolicy::$plugin;
    $originalEnableAuditLog = $plugin->getSettings()->enableAuditLog;
    $plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $id = $plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');

    expect($id)->toBeInt();

    $row = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $id])
        ->one();

    // Recompute the row's rowHash exactly as the verifier does: canonicalise
    // the stored immutable columns through the kit, hash against the stored
    // previousHash (the genesis sentinel for the first row).
    $recomputed = hash('sha256', AuditLogService::canonicalize([
        'changedByIdentifier' => $row['changedByIdentifier'],
        'dateCreated' => (new DateTime((string)$row['dateCreated'], new DateTimeZone('UTC')))
            ->format(AuditLogService::CANONICAL_DATE_FORMAT),
        'details' => null,
        'event' => $row['event'],
        'ipHash' => $row['ipHash'],
        'outcome' => $row['outcome'],
        'source' => $row['source'],
        'uid' => $row['uid'],
        'userIdentifier' => $row['userIdentifier'],
    ]) . $row['previousHash']);

    expect($row['previousHash'])->toBe(AuditLogService::GENESIS_PREVIOUS_HASH);
    expect($recomputed)->toBe($row['rowHash']);

    $plugin->getSettings()->enableAuditLog = $originalEnableAuditLog;
});
