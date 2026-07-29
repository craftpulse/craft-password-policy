<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Pest coverage for the F1 chain-write-failure recovery path: a failed
 * inline write through the Enterprise Audit Kit `ChainWriter` must never
 * silently drop the event. `AuditLogService::logEvent()` escalates the
 * failure to an error-level log carrying the full event payload and hands
 * the event to the deferred `WriteAuditChainEntryJob` for a bounded,
 * jittered-backoff retry rather than swallowing it, mirroring
 * craft-ledger's `LedgerLog` / `WriteChainEntry` pattern.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\jobs\WriteAuditChainEntryJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the most recently pushed job on the queue table that lands after
 * `$afterId`, unserialized, or `null` when nothing new landed.
 */
function ppPushedJobAfter(int $afterId): ?object
{
    $row = (new Query())
        ->from('{{%queue}}')
        ->where(['>', 'id', $afterId])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    return $row === false || $row === null ? null : unserialize($row['job']);
}

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    // Queue pushes commit outside the per-test transaction wrap — record a
    // high-water mark so cleanup below only touches rows this test added.
    $this->queueHighWaterMark = (int)((new Query())->from('{{%queue}}')->max('id') ?? 0);
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%queue}}', ['>', 'id', $this->queueHighWaterMark])
        ->execute();
});

// =============================================================================
// F1 — never silently drop a chain-write failure
// =============================================================================

it('requeues through WriteAuditChainEntryJob when an inline chain write fails, never silently dropping it', function() {
    $plugin = $this->plugin;
    $originalService = $plugin->getAuditLog();

    $throwingService = new class extends AuditLogService {
        public function writePrepared(array $data): int
        {
            throw new RuntimeException('simulated chain-write failure');
        }
    };

    $plugin->set('auditLog', $throwingService);

    try {
        $id = $plugin->getAuditLog()->logEvent(
            userId: null,
            event: 'password_changed',
        );
    } finally {
        $plugin->set('auditLog', $originalService);
    }

    // The failed inline write returns null (never blocks the caller) — but
    // it must not vanish. No row landed synchronously...
    expect($id)->toBeNull();

    $exists = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'password_changed'])
        ->exists();
    expect($exists)->toBeFalse();

    // ...because it was requeued through WriteAuditChainEntryJob instead of
    // dropped, carrying the full event payload forward for the retry.
    $job = ppPushedJobAfter($this->queueHighWaterMark);

    expect($job)->toBeInstanceOf(WriteAuditChainEntryJob::class);
    assert($job instanceof WriteAuditChainEntryJob);
    expect($job->data['event'])->toBe('password_changed');
    expect($job->data['outcome'])->toBe('success');
    expect($job->requeueAttempt)->toBe(0);
});

it('requeues itself with backoff when the deferred job\'s own write attempt fails, carrying the payload forward', function() {
    $plugin = $this->plugin;
    $originalService = $plugin->getAuditLog();

    $throwingService = new class extends AuditLogService {
        public function writePrepared(array $data): int
        {
            throw new RuntimeException('simulated chain-write failure');
        }
    };

    $plugin->set('auditLog', $throwingService);

    $job = new WriteAuditChainEntryJob([
        'data' => ['event' => 'test.deferred-failure', 'outcome' => 'success'],
    ]);

    try {
        $job->execute(Craft::$app->getQueue());
    } finally {
        $plugin->set('auditLog', $originalService);
    }

    $retried = ppPushedJobAfter($this->queueHighWaterMark);

    expect($retried)->toBeInstanceOf(WriteAuditChainEntryJob::class);
    assert($retried instanceof WriteAuditChainEntryJob);
    expect($retried->requeueAttempt)->toBe(1);
    expect($retried->data['event'])->toBe('test.deferred-failure');
});

it('increments the requeue attempt on each subsequent failure', function() {
    $plugin = $this->plugin;
    $originalService = $plugin->getAuditLog();

    $throwingService = new class extends AuditLogService {
        public function writePrepared(array $data): int
        {
            throw new RuntimeException('simulated chain-write failure');
        }
    };

    $plugin->set('auditLog', $throwingService);

    $job = new WriteAuditChainEntryJob([
        'data' => ['event' => 'test.deferred-failure-2', 'outcome' => 'success'],
        'requeueAttempt' => 1,
    ]);

    try {
        $job->execute(Craft::$app->getQueue());
    } finally {
        $plugin->set('auditLog', $originalService);
    }

    $retried = ppPushedJobAfter($this->queueHighWaterMark);

    expect($retried)->toBeInstanceOf(WriteAuditChainEntryJob::class);
    assert($retried instanceof WriteAuditChainEntryJob);
    expect($retried->requeueAttempt)->toBe(2);
});

it('gives up loudly after the max requeue attempts, without requeuing again', function() {
    $plugin = $this->plugin;
    $originalService = $plugin->getAuditLog();

    $throwingService = new class extends AuditLogService {
        public function writePrepared(array $data): int
        {
            throw new RuntimeException('simulated chain-write failure');
        }
    };

    $plugin->set('auditLog', $throwingService);

    $job = new WriteAuditChainEntryJob([
        'data' => ['event' => 'test.exhausted', 'outcome' => 'success'],
        'requeueAttempt' => WriteAuditChainEntryJob::MAX_REQUEUE_ATTEMPTS,
    ]);

    try {
        $job->execute(Craft::$app->getQueue());
    } finally {
        $plugin->set('auditLog', $originalService);
    }

    expect(ppPushedJobAfter($this->queueHighWaterMark))->toBeNull();
});

it('lands the row normally through the job when the retried write eventually succeeds', function() {
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}', ['event' => 'test.deferred-success'])
        ->execute();

    $job = new WriteAuditChainEntryJob([
        'data' => [
            'userId' => null,
            'changedByUserId' => null,
            'event' => 'test.deferred-success',
            'outcome' => 'success',
            'source' => 'console',
            'details' => null,
            'ipHash' => null,
            'geoCountry' => null,
            'geoRegion' => null,
            'userIdentifier' => null,
            'changedByIdentifier' => null,
            'dateCreated' => (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s\Z'),
            'uid' => \craft\helpers\StringHelper::UUID(),
        ],
    ]);

    $job->execute(Craft::$app->getQueue());

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'test.deferred-success'])
        ->one();

    expect($row)->not->toBeFalse();

    // Own cleanup — this row lands through the queue's own DB connection,
    // outside the per-test transaction wrap.
    Craft::$app->getDb()->createCommand()->delete('{{%elements}}', ['id' => $row['id']])->execute();
});
