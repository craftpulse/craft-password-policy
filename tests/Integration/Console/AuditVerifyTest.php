<?php
/**
 * Pest coverage for `AuditController::actionVerify` — the G2
 * independent verifier CLI. Pins:
 *
 *  - Exit codes (0 valid, 1 chain break, 2 unreadable).
 *  - Per-row OK lines + summary lines + JSON Lines mode.
 *  - `--quiet` suppresses per-row OK output.
 *  - `--from` / `--to` bounded walks (corruption outside the range
 *    is not detected, by design).
 *  - Retention-purged-row tolerance: full-walk + first surviving row
 *    older than `auditLogRetentionDays + 24h` accepts the
 *    non-genesis `previousHash` as a chain start.
 *  - Two distinct break reasons — `rowHash mismatch` vs
 *    `previousHash mismatch` — emitted in JSON output so consumers
 *    can route them.
 *
 * Stdout/stderr capture: `Yii\console\Controller::stdout/stderr`
 * write via `fwrite(\STDOUT|\STDERR, …)`, which PHP output buffering
 * doesn't catch. Tests subclass the controller and override both
 * methods to append into capture properties — the
 * production-controller path stays untouched.
 *
 * Tampering simulation uses a raw `UPDATE` because the writer service
 * is read-only by design — there's no admin "edit row" surface to
 * exercise. This is the only test path that touches the audit table
 * outside the chain-aware writer.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\helpers\Json;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\CapturingAuditController;

// =============================================================================
// Setup — flip enableAuditLog on for every test, wipe rows, restore after
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;
    $this->originalRetentionDays = $this->plugin->getSettings()->auditLogRetentionDays;

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
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
    $this->plugin->getSettings()->auditLogRetentionDays = $this->originalRetentionDays;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns a fresh capture-friendly subclass instance — overrides
 * stdout/stderr to append into arrays the test can assert on. Each
 * test gets a fresh instance because Pest re-runs `beforeEach` per
 * test and stale buffers across tests would alias assertions.
 */
function newVerifier(): CapturingAuditController
{
    return new CapturingAuditController('audit', PasswordPolicy::$plugin);
}

/**
 * Issues a raw UPDATE against the audit table to simulate tampering.
 * The writer service has no edit path by design; raw SQL is the only
 * way to corrupt a row mid-test. Mirrors the manual playground gate
 * (`UPDATE passwordpolicy_audit_log SET event = '…' WHERE id = X`).
 *
 * @param int $id
 * @param array<string, mixed> $columnChanges
 */
function tamperRow(int $id, array $columnChanges): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_audit_log}}',
            $columnChanges,
            ['id' => $id],
        )
        ->execute();
}

/**
 * @return array<int, array<string, mixed>>
 */
function fetchAllRows(): array
{
    return (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();
}

// =============================================================================
// Empty audit log → exit 0
// =============================================================================

it('returns exit 0 with "OK: 0 rows verified" on an empty audit log', function() {
    $verifier = newVerifier();
    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(0);
    expect(implode('', $verifier->stdoutBuffer))->toContain('OK: 0 rows verified');
});

// =============================================================================
// Single-row chain → exit 0
// =============================================================================

it('returns exit 0 on a single valid genesis row', function() {
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');

    $verifier = newVerifier();
    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(0);
    $output = implode('', $verifier->stdoutBuffer);
    expect($output)->toContain('OK: row');
    expect($output)->toContain('OK: 1 rows verified');
});

// =============================================================================
// Three-row valid chain → exit 0
// =============================================================================

it('returns exit 0 on a three-row valid chain', function() {
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');

    $verifier = newVerifier();
    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(0);
    expect(implode('', $verifier->stdoutBuffer))->toContain('OK: 3 rows verified');
});

// =============================================================================
// Tampered row's `event` column → exit 1, names the row
// =============================================================================

it('returns exit 1 when row 2 event column is tampered', function() {
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');

    $rows = fetchAllRows();
    tamperRow((int)$rows[1]['id'], ['event' => 'tampered']);

    $verifier = newVerifier();
    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(1);

    $stderr = implode('', $verifier->stderrBuffer);
    expect($stderr)->toContain((string)$rows[1]['id']);
    expect($stderr)->toContain('rowHash mismatch');
});

// =============================================================================
// Tampered previousHash → exit 1 with previousHash mismatch
// =============================================================================

it('returns exit 1 when row 2 previousHash is tampered', function() {
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');

    $rows = fetchAllRows();
    // Replace row 2's previousHash with a sham 64-char hex digest. The
    // computed rowHash for row 2 will also drift (because it depends
    // on previousHash), so this surfaces the previousHash break first
    // — that's the chain-walk's contract: rowHash recomputes against
    // the stored previousHash, but the previousHash check against the
    // prior row's stored rowHash runs first.
    $shamHash = str_repeat('f', 64);
    tamperRow((int)$rows[1]['id'], ['previousHash' => $shamHash]);

    $verifier = newVerifier();
    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(1);

    $stderr = implode('', $verifier->stderrBuffer);
    expect($stderr)->toContain((string)$rows[1]['id']);
    expect($stderr)->toContain('previousHash mismatch');
});

// =============================================================================
// Retention boundary: first surviving row older than retention + 24h → exit 0
// =============================================================================

it('accepts non-genesis previousHash on a row older than retention + 24h', function() {
    // Build a chain, then simulate retention-purge by deleting row 1
    // and back-dating row 2's dateCreated to predate the retention
    // boundary.
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');

    $rows = fetchAllRows();
    expect($rows)->toHaveCount(2);

    // Delete the genesis row. Row 2's previousHash now references a
    // row that no longer exists — legitimate retention scenario.
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}', ['id' => $rows[0]['id']])
        ->execute();

    // Back-date row 2 to be older than retention + 24h. Default
    // retention is 365 days; 367 days back puts it comfortably past
    // the safety margin.
    $oldDate = (new \DateTime('-367 days', new \DateTimeZone('UTC')))
        ->format('Y-m-d H:i:s');
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_audit_log}}',
            ['dateCreated' => $oldDate],
            ['id' => $rows[1]['id']],
        )
        ->execute();

    // Recompute the surviving row's rowHash using its new dateCreated
    // — the writer hashed against the original dateCreated, but a
    // legitimate retention-pruned chain would have row 2's hash
    // anchored to its actual dateCreated string. Re-stamp via
    // canonicalize() so the verifier's recompute matches.
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $rows[1]['id']])
        ->one();

    $payload = \craftpulse\passwordpolicy\services\AuditLogService::canonicalize([
        'changedByUserId' => $row['changedByUserId'] !== null
            ? (int)$row['changedByUserId']
            : null,
        'dateCreated' => (new \DateTime($row['dateCreated'], new \DateTimeZone('UTC')))
            ->format('Y-m-d\TH:i:s\Z'),
        'details' => null,
        'event' => $row['event'],
        'ipHash' => $row['ipHash'],
        'outcome' => $row['outcome'],
        'source' => $row['source'],
        'uid' => $row['uid'],
        'userId' => $row['userId'] !== null ? (int)$row['userId'] : null,
        'userIdentifier' => $row['userIdentifier'],
    ]);
    $newRowHash = hash('sha256', $payload . $row['previousHash']);

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_audit_log}}',
            ['rowHash' => $newRowHash],
            ['id' => $rows[1]['id']],
        )
        ->execute();

    $verifier = newVerifier();
    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(0);
});

// =============================================================================
// Retention boundary failure: recent first row with non-genesis previousHash → exit 1
// =============================================================================

it('returns exit 1 when first surviving row is recent with a non-genesis previousHash', function() {
    // Two rows, then delete the genesis row. Row 2's dateCreated stays
    // recent — verifier must NOT accept this as a retention boundary.
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');

    $rows = fetchAllRows();
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}', ['id' => $rows[0]['id']])
        ->execute();

    $verifier = newVerifier();
    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(1);
    expect(implode('', $verifier->stderrBuffer))->toContain('previousHash mismatch');
});

// =============================================================================
// `--from` / `--to` bounds: corruption outside the range → exit 0
// =============================================================================

it('does not detect corruption outside the bounded --from / --to range', function() {
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');

    $rows = fetchAllRows();
    // Corrupt row 1 (outside the upcoming --from=row2-id range).
    tamperRow((int)$rows[0]['id'], ['event' => 'tampered_outside_range']);

    $verifier = newVerifier();
    // Bounded walk skips row 1 entirely. Rows 2 and 3 are intact and
    // chain to each other; but since --from is set, retention boundary
    // tolerance is OFF, and row 2's previousHash references row 1's
    // (now stale) rowHash. Row 1 wasn't re-hashed by tamperRow — its
    // stored rowHash is unchanged — so row 2's previousHash still
    // matches. The verifier walks 2-3 cleanly.
    $verifier->from = (int)$rows[1]['id'];
    $verifier->to = (int)$rows[2]['id'];

    $exitCode = $verifier->runAction('verify');

    expect($exitCode)->toBe(0);
    expect(implode('', $verifier->stdoutBuffer))->toContain('OK: 2 rows verified');
});

// =============================================================================
// JSON output is parseable JSON Lines
// =============================================================================

it('emits parseable JSON Lines under --json with a final summary line', function() {
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');

    $verifier = newVerifier();
    $verifier->json = true;

    $exitCode = $verifier->runAction('verify');
    expect($exitCode)->toBe(0);

    $lines = array_filter(
        explode("\n", implode('', $verifier->stdoutBuffer)),
        static fn(string $line): bool => $line !== '',
    );
    $lines = array_values($lines);

    expect($lines)->toHaveCount(3); // 2 rows + 1 summary

    foreach ($lines as $line) {
        expect(Json::decode($line))->toBeArray();
    }

    $summary = Json::decode($lines[2]);
    expect($summary)->toHaveKey('summary');
    expect($summary['summary']['totalRows'])->toBe(2);
    expect($summary['summary']['verifiedRows'])->toBe(2);
    expect($summary['summary']['exitCode'])->toBe(0);
});

// =============================================================================
// `--quiet` suppresses per-row OK lines
// =============================================================================

it('suppresses per-row OK lines under --quiet', function() {
    $service = $this->plugin->getAuditLog();
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');

    $verifier = newVerifier();
    $verifier->quiet = true;

    $exitCode = $verifier->runAction('verify');
    expect($exitCode)->toBe(0);

    $output = implode('', $verifier->stdoutBuffer);
    expect($output)->not->toContain('OK: row');
    expect($output)->toContain('OK: 2 rows verified');
});
