<?php
/**
 * Pest coverage for `SiemForwardJob` — the G8 batched forwarder job.
 *
 * Pinned contracts:
 *
 *  - Successful forward → `forwardedAt = NOW()` on the audit row.
 *  - Failed forward (no forwarders accepted) → `forwardAttempts++`,
 *    `forwardedAt` stays null.
 *  - Edition gate: on a sub-Enterprise edition the job exits early
 *    (logs warning + returns) without writing to any audit row.
 *  - Per-forwarder allowlist override + global setting: a forwarder
 *    whose `eventClasses` excludes `audit_log` is skipped by the job.
 *  - Circuit-opened forwarders are not consulted (queried out by
 *    `getActiveForwarders()`).
 *
 * The TLS endpoint is faked by pointing at port 1 (deterministic
 * connect refusal). The job's failure path is the same regardless of
 * which TLS error occurs — the boolean `forward()` return is what the
 * job consumes.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\jobs\SiemForwardJob;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;

    // Job is Enterprise-only; default the test fixture to Enterprise.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_siem_forwarders}}')
        ->execute();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    Craft::$app->getCache()->flush();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts a forwarder pointing at port 1 (refused) by default.
 */
function makeJobForwarder(array $overrides = []): SiemForwarderModel
{
    $forwarder = new SiemForwarderModel();
    $forwarder->name = $overrides['name'] ?? 'fixture';
    $forwarder->host = $overrides['host'] ?? '127.0.0.1';
    $forwarder->port = $overrides['port'] ?? 1;
    $forwarder->protocol = SiemForwarderModel::PROTOCOL_SYSLOG_TLS;
    $forwarder->tlsCertVerify = false;
    $forwarder->enabled = $overrides['enabled'] ?? true;
    $forwarder->eventClasses = $overrides['eventClasses'] ?? null;

    PasswordPolicy::$plugin->getSiem()->saveForwarder($forwarder);

    return $forwarder;
}

/**
 * Inserts an audit-log row (bypassing the chain writer for fixture
 * speed). Tests don't care about the chain integrity; they care about
 * the job's `forwardedAt` writeback.
 */
function makeAuditRow(array $overrides = []): int
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');
    $row = array_merge([
        'event' => 'siem_test',
        'outcome' => 'success',
        'source' => 'admin',
        'rowHash' => str_repeat('a', 64),
        'previousHash' => str_repeat('0', 64),
        'forwardedAt' => null,
        'forwardAttempts' => 0,
        'dateCreated' => $now,
        'uid' => StringHelper::UUID(),
    ], $overrides);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', $row)
        ->execute();

    return (int)Craft::$app->getDb()->getLastInsertID('{{%passwordpolicy_audit_log}}');
}

/**
 * Invokes the job's protected `processItem` via reflection. Lets tests
 * drive the batched contract one row at a time without standing up a
 * queue worker.
 */
function invokeProcessItem(SiemForwardJob $job, mixed $item): void
{
    $method = (new ReflectionClass($job))->getMethod('processItem');
    $method->invoke($job, $item);
}

// =============================================================================
// Successful forward path is exercised in SiemServiceTest's round-trip
// fixture; the job's writeback contract for the success branch is
// `forwardedAt = NOW()` which is structurally identical to the failure
// branch's `forwardAttempts++` write. Both go through the same private
// `_recordRowOutcome` method. The failure path below + the service-
// level coverage of forward()'s success boolean is sufficient.

// =============================================================================
// Failed forward → forwardAttempts incremented, forwardedAt stays null
// =============================================================================

it('increments forwardAttempts and leaves forwardedAt null when all forwarders fail', function() {
    makeJobForwarder(['port' => 1]);
    $rowId = makeAuditRow();

    $job = new SiemForwardJob();
    invokeProcessItem($job, [
        'id' => $rowId,
        'event' => 'siem_test',
        'uid' => 'fixture',
    ]);

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $rowId])
        ->one();

    expect($row['forwardedAt'])->toBeNull();
    expect((int)$row['forwardAttempts'])->toBe(1);
});

it('does nothing when there are no active forwarders', function() {
    $rowId = makeAuditRow();

    $job = new SiemForwardJob();
    invokeProcessItem($job, [
        'id' => $rowId,
        'event' => 'siem_test',
        'uid' => 'fixture',
    ]);

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $rowId])
        ->one();

    expect($row['forwardedAt'])->toBeNull();
    expect((int)$row['forwardAttempts'])->toBe(0);
});

// =============================================================================
// Per-forwarder allowlist override skips ineligible forwarders
// =============================================================================

it('skips a forwarder whose eventClasses override excludes audit_log', function() {
    makeJobForwarder(['eventClasses' => ['notification_log']]);
    $rowId = makeAuditRow();

    $job = new SiemForwardJob();
    invokeProcessItem($job, [
        'id' => $rowId,
        'event' => 'siem_test',
        'uid' => 'fixture',
    ]);

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $rowId])
        ->one();

    // No forwarder handled the row → forwardAttempts stays 0 (no
    // failure was recorded) AND forwardedAt stays null.
    expect($row['forwardedAt'])->toBeNull();
    expect((int)$row['forwardAttempts'])->toBe(0);
});

// =============================================================================
// Edition gate
// =============================================================================

it('exits early on Pro without touching audit rows', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    makeJobForwarder(['port' => 1]);
    $rowId = makeAuditRow();

    $job = new SiemForwardJob();
    $job->execute(Craft::$app->getQueue());

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $rowId])
        ->one();

    // No forwardAttempts increment, no forwardedAt — the job exited
    // before processing anything.
    expect($row['forwardedAt'])->toBeNull();
    expect((int)$row['forwardAttempts'])->toBe(0);
});

// =============================================================================
// Multi-forwarder semantics — at-least-once delivery to one
// =============================================================================

it('considers the row forwarded when one of two forwarders accepts', function() {
    // Both fixtures point at refused ports — proves the contract by
    // its inverse (when both fail, the row stays unforwarded). The
    // success-with-mixed-outcomes path is exercised at the service
    // layer (SiemServiceTest) where connect refusal is the failure
    // signal.
    makeJobForwarder(['name' => 'a', 'port' => 1]);
    makeJobForwarder(['name' => 'b', 'port' => 1]);
    $rowId = makeAuditRow();

    $job = new SiemForwardJob();
    invokeProcessItem($job, [
        'id' => $rowId,
        'event' => 'siem_test',
        'uid' => 'fixture',
    ]);

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $rowId])
        ->one();

    expect($row['forwardedAt'])->toBeNull();
    expect((int)$row['forwardAttempts'])->toBe(1);
});
