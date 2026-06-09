<?php
/**
 * Pest coverage for `AuditLogService::EVENT_AUDIT_CHAIN_ROTATED` — the
 * Phase G observability seam fired when the retention prune deletes one
 * or more rows.
 *
 * Contract:
 *
 *  - Fires once per successful prune that deleted >= 1 row AND left
 *    >= 1 row standing.
 *  - Payload: `(startId, startRowHash, endId, endRowHash, rotatedAt)`.
 *    Consumers use the start pair to anchor the verifier's next walk
 *    and the end pair to record the rotation boundary externally.
 *  - Skipped when the prune deleted zero rows OR emptied the table.
 *
 * Tests bypass the playground's audit-log feature flag by toggling
 * `enableAuditLog` and seed rows directly via the chain-aware
 * `logEvent()` so the rotation event sees real chain data, not test
 * placeholders.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craftpulse\passwordpolicy\events\AuditChainRotatedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use yii\base\Event;

// =============================================================================
// Setup — flip enableAuditLog on, wipe pre-existing rows
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
    Event::off(AuditLogService::class, AuditLogService::EVENT_AUDIT_CHAIN_ROTATED);
});

// =============================================================================
// Helper — back-date a row's `dateCreated` so the prune deletes it
// =============================================================================

function backdateAuditRow(int $id, string $dateCreated): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_audit_log}}',
            ['dateCreated' => $dateCreated],
            ['id' => $id],
        )
        ->execute();
}

// =============================================================================
// Fires with correct payload after a successful prune
// =============================================================================

it('fires AuditChainRotatedEvent when the prune deletes rows but leaves a head', function() {
    $service = $this->plugin->getAuditLog();

    // Seed three chained rows. We'll back-date the first two to make the
    // prune drop them, leaving row 3 as the new chain head.
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    expect($rows)->toHaveCount(3);

    $oldThreshold = Carbon::now('UTC')->subDays(10)->format('Y-m-d H:i:s');
    backdateAuditRow((int)$rows[0]['id'], $oldThreshold);
    backdateAuditRow((int)$rows[1]['id'], $oldThreshold);

    $captured = null;
    Event::on(
        AuditLogService::class,
        AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
        function(AuditChainRotatedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $deleted = $service->purgeOldEntries(daysToKeep: 5);

    expect($deleted)->toBe(2);
    expect($captured)->toBeInstanceOf(AuditChainRotatedEvent::class);
    expect($captured->endId)->toBe((int)$rows[1]['id']);
    expect($captured->endRowHash)->toBe($rows[1]['rowHash']);
    expect($captured->startId)->toBe((int)$rows[2]['id']);
    expect($captured->startRowHash)->toBe($rows[2]['rowHash']);
    expect($captured->rotatedAt)->toBeInstanceOf(\DateTime::class);
});

// =============================================================================
// endRowHash equals the surviving head's previousHash (rotation boundary)
// =============================================================================

it('publishes the surviving head previousHash as endRowHash', function() {
    $service = $this->plugin->getAuditLog();

    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    $oldThreshold = Carbon::now('UTC')->subDays(10)->format('Y-m-d H:i:s');
    backdateAuditRow((int)$rows[0]['id'], $oldThreshold);
    backdateAuditRow((int)$rows[1]['id'], $oldThreshold);

    $captured = null;
    Event::on(
        AuditLogService::class,
        AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
        function(AuditChainRotatedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $deleted = $service->purgeOldEntries(daysToKeep: 5);

    expect($deleted)->toBe(2);
    expect($captured)->toBeInstanceOf(AuditChainRotatedEvent::class);

    // endId is the highest deleted id; endRowHash is the surviving
    // head's previousHash — which IS the rowHash of that highest
    // deleted row, the rotation boundary the verifier anchors against.
    expect($captured->endId)->toBe((int)$rows[1]['id']);
    expect($captured->endRowHash)->toBe($rows[2]['previousHash']);
    expect($captured->endRowHash)->toBe($rows[1]['rowHash']);
    expect($captured->startId)->toBe((int)$rows[2]['id']);
    expect($captured->startRowHash)->toBe($rows[2]['rowHash']);
});

// =============================================================================
// Clock-skew safety: prune removes a contiguous id prefix even when a
// higher-id row carries an OLDER dateCreated (no mid-chain hole)
// =============================================================================

it('prunes by a contiguous id boundary so a clock-skewed row never punches a mid-chain hole', function() {
    $service = $this->plugin->getAuditLog();

    // Seed four chained rows.
    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');
    $service->logEvent(userId: null, event: 'account_unlocked');
    $service->logEvent(userId: null, event: 'password_changed');

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();
    expect($rows)->toHaveCount(4);

    $old = Carbon::now('UTC')->subDays(10)->format('Y-m-d H:i:s');
    $recent = Carbon::now('UTC')->format('Y-m-d H:i:s');

    // The dangerous case the id-boundary fix guards against: an OLD-dated
    // row sitting at a HIGHER id than a RECENT row (a backward clock step
    // stamped row 2 with an old date while the lower-id row 1 stayed
    // recent). The OLD `DELETE WHERE dateCreated < threshold` code would
    // drop ONLY row 2 — punching a mid-chain hole (rows 1, 3, 4 survive,
    // 2 missing). The fix resolves `maxId = MAX(id) WHERE dateCreated <
    // threshold` (= row 2's id) and deletes the whole `id <= maxId`
    // prefix, so the survivors are always a contiguous, unbroken suffix —
    // it sacrifices the recent row 1 to keep the chain whole. This setup
    // FAILS against the pre-fix code (which would delete 1 row, not 2).
    backdateAuditRow((int)$rows[0]['id'], $recent);
    backdateAuditRow((int)$rows[1]['id'], $old);
    backdateAuditRow((int)$rows[2]['id'], $recent);
    backdateAuditRow((int)$rows[3]['id'], $recent);

    $deleted = $service->purgeOldEntries(daysToKeep: 5);

    // The whole id<=row2 prefix (rows 1-2) is gone — including the recent
    // row 1 — so rows 3-4 survive as a clean, hole-free chain suffix.
    expect($deleted)->toBe(2);

    $survivors = (new \craft\db\Query())
        ->select(['id'])
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->column();

    expect(array_map('intval', $survivors))->toBe([
        (int)$rows[2]['id'],
        (int)$rows[3]['id'],
    ]);
});

// =============================================================================
// Skips the event when the prune deleted zero rows
// =============================================================================

it('does not fire when the prune deletes zero rows', function() {
    $service = $this->plugin->getAuditLog();

    $service->logEvent(userId: null, event: 'password_changed');

    $captured = null;
    Event::on(
        AuditLogService::class,
        AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
        function(AuditChainRotatedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $deleted = $service->purgeOldEntries(daysToKeep: 365);

    expect($deleted)->toBe(0);
    expect($captured)->toBeNull();
});

// =============================================================================
// Skips the event when the prune emptied the table (no surviving head)
// =============================================================================

it('does not fire when the prune emptied the table', function() {
    $service = $this->plugin->getAuditLog();

    $service->logEvent(userId: null, event: 'password_changed');
    $service->logEvent(userId: null, event: 'account_locked');

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    $oldThreshold = Carbon::now('UTC')->subDays(10)->format('Y-m-d H:i:s');
    foreach ($rows as $row) {
        backdateAuditRow((int)$row['id'], $oldThreshold);
    }

    $captured = null;
    Event::on(
        AuditLogService::class,
        AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
        function(AuditChainRotatedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $deleted = $service->purgeOldEntries(daysToKeep: 5);

    expect($deleted)->toBe(2);
    expect($captured)->toBeNull();
});
